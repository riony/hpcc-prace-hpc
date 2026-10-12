// prace-nri-mount-guard: a containerd NRI plugin that gives the share mounts of the Slurm pods (T87)
// nosuid and nodev inside the container. kubelet mounts the NFS volumes with them, but containerd
// passes the volume to runc as [rbind, rprivate, rw|ro] and the container's bind mount drops them
// (3 Oct, runbook step 5). The plugin adds the options to those mounts before the container is
// created; a guarded mount it cannot guard refuses the container.
//
// It runs as a systemd service on every K3s node and connects to containerd's NRI socket. While it is
// not connected containers start unadjusted, so the pods check their own mounts before sshd or slurmd
// starts (the chart's share check) and refuse to start without the options.
//
// usage: prace-nri-mount-guard -namespace slurm -path /home -path /projects -path /apps
//
//	[-socket /var/run/nri/nri.sock] [-ready /run/prace-nri-mount-guard/ready]
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
)

const pluginName, pluginIdx = "prace-mount-guard", "10"

type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

type plugin struct {
	guard *guard
	ready string
}

// Configure is called once containerd has accepted the plugin: only then is it ready, and the ready
// file says so (with this process's PID, so a leftover file of an earlier process does not count).
func (p *plugin) Configure(_ context.Context, _, runtime, version string) (api.EventMask, error) {
	log.Printf("registered with %s %s", runtime, version)
	if p.ready != "" {
		if err := os.MkdirAll(filepath.Dir(p.ready), 0o755); err != nil {
			return 0, err
		}
		line := fmt.Sprintf("pid=%d runtime=%s version=%s since=%s\n", os.Getpid(), runtime, version, time.Now().UTC().Format(time.RFC3339))
		tmp := p.ready + ".tmp"
		if err := os.WriteFile(tmp, []byte(line), 0o644); err != nil {
			return 0, err
		}
		if err := os.Rename(tmp, p.ready); err != nil {
			return 0, err
		}
	}
	return api.MustParseEventMask("CreateContainer"), nil
}

func (p *plugin) CreateContainer(_ context.Context, pod *api.PodSandbox, ctr *api.Container) (*api.ContainerAdjustment, []*api.ContainerUpdate, error) {
	mounts, err := p.guard.adjust(pod, ctr)
	if err != nil {
		log.Printf("refused: %v", err)
		return nil, nil, err
	}
	if len(mounts) == 0 {
		return nil, nil, nil
	}
	adjust := &api.ContainerAdjustment{}
	names := []string{}
	for _, m := range mounts {
		adjust.AddMount(m)
		names = append(names, m.Destination)
	}
	log.Printf("%s/%s container %s: nosuid,nodev on %s", pod.GetNamespace(), pod.GetName(), ctr.GetName(), strings.Join(names, ","))
	return adjust, nil, nil
}

func main() {
	var namespaces, paths list
	flag.Var(&namespaces, "namespace", "pod namespace whose containers are guarded (repeatable)")
	flag.Var(&paths, "path", "container path of a share mount to guard (repeatable)")
	socket := flag.String("socket", "", "containerd's NRI socket (default: NRI's default)")
	ready := flag.String("ready", "/run/prace-nri-mount-guard/ready", "file written once registered, removed on exit ('' for none)")
	flag.Parse()
	log.SetFlags(0)

	g, err := newGuard(namespaces, paths)
	if err != nil {
		log.Fatalf("configuration: %v", err)
	}
	p := &plugin{guard: g, ready: *ready}
	if p.ready != "" {
		_ = os.Remove(p.ready) // an earlier process's file never counts
		defer os.Remove(p.ready)
	}
	opts := []stub.Option{
		stub.WithPluginName(pluginName),
		stub.WithPluginIdx(pluginIdx),
		// containerd restarted or dropped the plugin: exit, so the service restarts and registers again
		stub.WithOnClose(func() {
			if p.ready != "" {
				_ = os.Remove(p.ready)
			}
			log.Fatalf("connection to the runtime closed")
		}),
	}
	if *socket != "" {
		opts = append(opts, stub.WithSocketPath(*socket))
	}
	s, err := stub.New(p, opts...)
	if err != nil {
		log.Fatalf("plugin: %v", err)
	}
	// systemd stops the service with SIGTERM: the ready file goes before the process does
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-signals
		if p.ready != "" {
			_ = os.Remove(p.ready)
		}
		log.Printf("stopping on %v", sig)
		os.Exit(0)
	}()
	log.Printf("guarding %v in namespaces %v", paths, namespaces)
	if err := s.Run(context.Background()); err != nil {
		if p.ready != "" {
			_ = os.Remove(p.ready)
		}
		log.Fatalf("plugin stopped: %v", err)
	}
}
