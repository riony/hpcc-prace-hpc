package main

import (
	"fmt"

	"github.com/containerd/nri/pkg/api"
)

// The options every guarded share mount must carry inside the container (T87). containerd hands a
// volume to runc as a bind mount with [rbind, rprivate, rw|ro], and the container's mount loses the
// nosuid,nodev of kubelet's NFS mount (3 Oct, runbook step 5). Naming them here makes runc set them.
var required = []string{"nosuid", "nodev"}

// The options that would undo them, if a mount ever named them.
var conflicting = map[string]bool{"suid": true, "dev": true}

// guard selects the containers and mount points to adjust: containers of pods in one of `namespaces`,
// mounts whose container path is one of `paths`.
type guard struct {
	namespaces map[string]bool
	paths      map[string]bool
}

func newGuard(namespaces, paths []string) (*guard, error) {
	if len(namespaces) == 0 || len(paths) == 0 {
		return nil, fmt.Errorf("at least one namespace and one path are required")
	}
	g := &guard{namespaces: map[string]bool{}, paths: map[string]bool{}}
	for _, n := range namespaces {
		g.namespaces[n] = true
	}
	for _, p := range paths {
		if len(p) < 2 || p[0] != '/' || p[len(p)-1] == '/' {
			return nil, fmt.Errorf("path %q must be absolute, without a trailing slash", p)
		}
		g.paths[p] = true
	}
	return g, nil
}

func has(options []string, want string) bool {
	for _, o := range options {
		if o == want {
			return true
		}
	}
	return false
}

// adjust returns the guarded mounts of a container again, each with its own type, source and options
// plus nosuid and nodev; NRI replaces a mount added at the same container path. Nil for a container
// outside the namespaces or without a guarded mount. A guarded mount that is not a bind mount, or
// that names suid or dev, is an error: the container is then not created at all.
func (g *guard) adjust(pod *api.PodSandbox, ctr *api.Container) ([]*api.Mount, error) {
	if !g.namespaces[pod.GetNamespace()] {
		return nil, nil
	}
	var out []*api.Mount
	for _, m := range ctr.GetMounts() {
		if !g.paths[m.GetDestination()] {
			continue
		}
		where := fmt.Sprintf("%s/%s container %s mount %s", pod.GetNamespace(), pod.GetName(), ctr.GetName(), m.GetDestination())
		if m.GetType() != "bind" && !has(m.GetOptions(), "bind") && !has(m.GetOptions(), "rbind") {
			return nil, fmt.Errorf("%s: not a bind mount (type %q, options %v)", where, m.GetType(), m.GetOptions())
		}
		for _, o := range m.GetOptions() {
			if conflicting[o] {
				return nil, fmt.Errorf("%s: names %q", where, o)
			}
		}
		options := append([]string{}, m.GetOptions()...)
		for _, o := range required {
			if !has(options, o) {
				options = append(options, o)
			}
		}
		out = append(out, &api.Mount{Destination: m.GetDestination(), Type: m.GetType(), Source: m.GetSource(), Options: options})
	}
	return out, nil
}
