package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/containerd/nri/pkg/api"
)

// The mounts containerd 2.3.4 passes for the slurmd pod's volumes (crictl inspect, 3 Oct).
func share(dest, mode string) *api.Mount {
	return &api.Mount{Destination: dest, Type: "bind",
		Source:  "/var/lib/kubelet/pods/uid/volumes/kubernetes.io~nfs/prace" + strings.ReplaceAll(dest, "/", "-"),
		Options: []string{"rbind", "rprivate", mode}}
}

func pod(ns string) *api.PodSandbox {
	return &api.PodSandbox{Name: "slurm-worker-cpu-x", Namespace: ns}
}

func ctr(mounts ...*api.Mount) *api.Container { return &api.Container{Name: "slurmd", Mounts: mounts} }

func mustGuard(t *testing.T) *guard {
	g, err := newGuard([]string{"slurm"}, []string{"/home", "/projects", "/apps"})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestGuardedSharesGainNosuidNodevAndKeepEverythingElse(t *testing.T) {
	other := &api.Mount{Destination: "/etc/slurm", Type: "bind", Source: "/x", Options: []string{"rbind", "ro"}}
	out, err := mustGuard(t).adjust(pod("slurm"), ctr(share("/home", "rw"), other, share("/apps", "ro")))
	if err != nil {
		t.Fatal(err)
	}
	want := []*api.Mount{
		{Destination: "/home", Type: "bind", Source: share("/home", "rw").Source, Options: []string{"rbind", "rprivate", "rw", "nosuid", "nodev"}},
		{Destination: "/apps", Type: "bind", Source: share("/apps", "ro").Source, Options: []string{"rbind", "rprivate", "ro", "nosuid", "nodev"}},
	}
	if !reflect.DeepEqual(out, want) {
		t.Fatalf("got %v, want %v", out, want)
	}
}

func TestOptionsAlreadyPresentAreNotRepeated(t *testing.T) {
	m := share("/projects", "rw")
	m.Options = append(m.Options, "nodev")
	out, err := mustGuard(t).adjust(pod("slurm"), ctr(m))
	if err != nil || len(out) != 1 || !reflect.DeepEqual(out[0].Options, []string{"rbind", "rprivate", "rw", "nodev", "nosuid"}) {
		t.Fatalf("got %v, %v", out, err)
	}
}

func TestTheInputIsNotModified(t *testing.T) {
	m := share("/home", "rw")
	if _, err := mustGuard(t).adjust(pod("slurm"), ctr(m)); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m.Options, []string{"rbind", "rprivate", "rw"}) {
		t.Fatalf("input changed: %v", m.Options)
	}
}

func TestOtherNamespacesAndPathsAreLeftAlone(t *testing.T) {
	g := mustGuard(t)
	for name, c := range map[string]struct {
		ns string
		m  *api.Mount
	}{
		"another namespace":      {"kube-system", share("/home", "rw")},
		"a path below a share":   {"slurm", share("/home/alice", "rw")},
		"a path that only looks": {"slurm", share("/homes", "rw")},
	} {
		out, err := g.adjust(pod(c.ns), ctr(c.m))
		if err != nil || out != nil {
			t.Errorf("%s: got %v, %v", name, out, err)
		}
	}
}

func TestAGuardedMountThatCannotBeGuardedRefusesTheContainer(t *testing.T) {
	g := mustGuard(t)
	notBind := &api.Mount{Destination: "/home", Type: "tmpfs", Source: "tmpfs", Options: []string{"rw"}}
	suid := share("/home", "rw")
	suid.Options = append(suid.Options, "suid")
	dev := share("/apps", "ro")
	dev.Options = append(dev.Options, "dev")
	for name, m := range map[string]*api.Mount{"not a bind mount": notBind, "suid": suid, "dev": dev} {
		if out, err := g.adjust(pod("slurm"), ctr(m)); err == nil {
			t.Errorf("%s: accepted (%v)", name, out)
		}
	}
}

func TestABindTypeNamedOnlyInTheOptionsCounts(t *testing.T) {
	m := share("/home", "rw")
	m.Type = ""
	out, err := mustGuard(t).adjust(pod("slurm"), ctr(m))
	if err != nil || len(out) != 1 || !has(out[0].Options, "nosuid") {
		t.Fatalf("got %v, %v", out, err)
	}
}

func TestTheConfigurationIsChecked(t *testing.T) {
	for name, c := range map[string][2][]string{
		"no namespace":   {nil, {"/home"}},
		"no path":        {{"slurm"}, nil},
		"relative path":  {{"slurm"}, {"home"}},
		"trailing slash": {{"slurm"}, {"/home/"}},
		"the root":       {{"slurm"}, {"/"}},
	} {
		if _, err := newGuard(c[0], c[1]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
