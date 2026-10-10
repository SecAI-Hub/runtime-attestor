//go:build linux

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

const fixtureContainerID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const fixtureImageID = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const fixtureOtherImage = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
const fixtureManifest = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

type containerFixture struct {
	cfg       ContainerConfig
	dir       string
	server    *http.Server
	mu        sync.Mutex
	calls     map[string]int
	change    func(string, int, any) any
	raw       func(http.ResponseWriter, *http.Request, int) bool
	list      []map[string]any
	container map[string]any
	image     map[string]any
	info      map[string]any
}

func newContainerFixture(t *testing.T, runtime string) *containerFixture {
	t.Helper()
	dir, err := os.MkdirTemp("", "ra-int13-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	uid, rootless, allow := uint32(os.Geteuid()), false, false
	hash, err := collectorMachineHash()
	if err != nil {
		t.Fatal(err)
	}
	f := &containerFixture{dir: dir, calls: map[string]int{}}
	f.cfg = ContainerConfig{IdentitySchema: 1, Scope: containerScope, Runtime: runtime, AllowEmpty: &allow,
		Source:        ContainerSource{Socket: filepath.Join(dir, "engine.sock"), PeerUID: &uid, MachineIDHash: hash, Version: "29.8.0", StorageRoot: "/fixture/storage", StorageDriver: "overlay2", DaemonID: "fixture-daemon", Rootless: &rootless},
		AllowedImages: []ContainerImage{{Name: "approved", Kind: "docker-config-id", EngineImageID: fixtureImageID, Platform: "linux/amd64"}},
		Required:      []ContainerService{{Name: "service", Image: "approved"}}, DenyUnlisted: true}
	f.list = []map[string]any{{"Id": fixtureContainerID, "Names": []string{"/service"}, "Image": "approved:latest", "ImageID": fixtureImageID, "State": "running"}}
	f.container = map[string]any{"Id": fixtureContainerID, "Name": "/service", "Image": fixtureImageID, "RestartCount": 0,
		"State":  map[string]any{"Running": true, "Paused": false, "Dead": false, "Restarting": false, "Status": "running", "StartedAt": "2026-09-08T01:02:03Z"},
		"Config": map[string]any{"Image": "approved:latest", "Env": []string{"PASSWORD=fixture-secret-do-not-report"}, "Labels": map[string]string{"approved": "true"}}}
	f.image = map[string]any{"Id": fixtureImageID, "Os": "linux", "Architecture": "amd64", "RootFS": map[string]any{"Type": "layers", "Layers": []string{fixtureOtherImage}}, "RepoTags": []string{"approved:latest"}, "RepoDigests": []string{"fake@" + fixtureImageID}}
	f.info = map[string]any{"ID": "fixture-daemon", "DockerRootDir": "/fixture/storage", "Driver": "overlay2", "ServerVersion": "29.8.0", "OSType": "linux", "Architecture": "x86_64", "SecurityOptions": []string{"name=seccomp,profile=builtin"}}
	if runtime == "podman" {
		f.cfg.Source.Version, f.cfg.Source.DaemonID, f.cfg.Source.RunRoot = "5.8.4", "", "/fixture/run"
		f.cfg.AllowedImages[0].Kind = "podman-image-id-v5"
		f.list[0]["Names"], f.list[0]["ImageID"] = []string{"service"}, strings.TrimPrefix(fixtureImageID, "sha256:")
		f.container["Name"], f.container["Image"], f.container["Namespace"] = "service", strings.TrimPrefix(fixtureImageID, "sha256:"), ""
		f.image["Id"] = strings.TrimPrefix(fixtureImageID, "sha256:")
		f.info = map[string]any{"version": map[string]any{"Version": "5.8.4"}, "host": map[string]any{"os": "linux", "arch": "amd64", "security": map[string]any{"rootless": false}}, "store": map[string]any{"graphRoot": "/fixture/storage", "runRoot": "/fixture/run", "graphDriverName": "overlay2"}}
	}
	listener, err := net.Listen("unix", f.cfg.Source.Socket)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.cfg.Source.Socket, 0600); err != nil {
		t.Fatal(err)
	}
	f.server = &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		key := r.URL.Path
		f.calls[key]++
		n := f.calls[key]
		prefix := "/v1.49/"
		if runtime == "podman" {
			prefix = "/v5.8.4/libpod/"
		}
		if r.Method != "GET" || r.Host != "container-endpoint" || !strings.HasPrefix(key, prefix) {
			http.Error(w, "bad request", 400)
			return
		}
		if f.raw != nil && f.raw(w, r, n) {
			return
		}
		var body any
		switch {
		case strings.HasSuffix(key, "/version"):
			body = map[string]any{"Version": "29.8.0", "Os": "linux", "Arch": "amd64"}
		case strings.HasSuffix(key, "/info"):
			if runtime == "docker" {
				f.info["ContainersRunning"] = len(f.list)
			} else {
				f.info["store"].(map[string]any)["containerStore"] = map[string]any{"running": len(f.list)}
			}
			body = f.info
		case strings.HasSuffix(key, "/containers/json"):
			if r.URL.RawQuery != "all=false" {
				http.Error(w, "unapproved inventory query", 400)
				return
			}
			body = f.list
		case strings.Contains(key, "/containers/"):
			body = f.container
		case strings.Contains(key, "/images/"):
			body = f.image
		default:
			http.NotFound(w, r)
			return
		}
		if f.change != nil {
			body = f.change(key, n, body)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})}
	done := make(chan struct{})
	go func() { defer close(done); _ = f.server.Serve(listener) }()
	t.Cleanup(func() { _ = f.server.Close(); <-done })
	return f
}

func requireContainerStatus(t *testing.T, f *containerFixture, want string) CollectorResult {
	t.Helper()
	got := collectContainerState(f.cfg)
	if got.Status != want {
		t.Fatalf("status=%s want=%s error=%s findings=%+v", got.Status, want, got.Error, got.Findings)
	}
	if want == "error" && (got.Error == "" || len(got.Findings) != 0) {
		t.Fatalf("error must not expose partial success: %+v", got)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "fixture-secret-do-not-report") || strings.Contains(string(b), "approved:latest") || strings.Contains(string(b), "RepoDigests") {
		t.Fatal("raw image names or inspect secrets leaked into report")
	}
	return got
}

func TestContainerImmutableIdentityAndServicePolicy(t *testing.T) {
	for _, runtime := range []string{"docker", "podman"} {
		t.Run(runtime, func(t *testing.T) {
			t.Run("approved immutable match", func(t *testing.T) {
				f := newContainerFixture(t, runtime)
				got := requireContainerStatus(t, f, "pass")
				if got.Findings[0].Key != "container_scope:endpoint-inventory" || !strings.Contains(got.Findings[0].Detail, "does not authenticate daemon host") {
					t.Fatal("scope missing")
				}
			})
			t.Run("replaced tag", func(t *testing.T) {
				f := newContainerFixture(t, runtime)
				f.list[0]["ImageID"], f.container["Image"], f.image["Id"] = fixtureOtherImage, fixtureOtherImage, fixtureOtherImage
				requireContainerStatus(t, f, "drift")
			})
			t.Run("foreign image", func(t *testing.T) {
				f := newContainerFixture(t, runtime)
				f.cfg.Required = nil
				f.cfg.DenyUnlisted = false
				f.list[0]["ImageID"], f.container["Image"], f.image["Id"] = fixtureOtherImage, fixtureOtherImage, fixtureOtherImage
				requireContainerStatus(t, f, "drift")
			})
			t.Run("missing required", func(t *testing.T) {
				f := newContainerFixture(t, runtime)
				f.list = []map[string]any{}
				requireContainerStatus(t, f, "drift")
			})
			t.Run("unlisted allowed image", func(t *testing.T) {
				f := newContainerFixture(t, runtime)
				f.cfg.Required = []ContainerService{{Name: "other", Image: "approved"}}
				requireContainerStatus(t, f, "drift")
			})
			t.Run("allowlist alone", func(t *testing.T) {
				f := newContainerFixture(t, runtime)
				f.cfg.Required = nil
				f.cfg.DenyUnlisted = false
				requireContainerStatus(t, f, "pass")
			})
			t.Run("empty forbidden", func(t *testing.T) {
				f := newContainerFixture(t, runtime)
				f.cfg.Required = nil
				f.list = []map[string]any{}
				requireContainerStatus(t, f, "drift")
			})
			t.Run("empty allowed", func(t *testing.T) {
				f := newContainerFixture(t, runtime)
				f.cfg.Required = nil
				*f.cfg.AllowEmpty = true
				f.list = []map[string]any{}
				requireContainerStatus(t, f, "pass")
			})
		})
	}
}

func TestContainerInspectFailures(t *testing.T) {
	cases := map[string]func(*containerFixture){
		"duplicate IDs": func(f *containerFixture) { f.list = append(f.list, f.list[0]) },
		"duplicate names": func(f *containerFixture) {
			f.list = append(f.list, map[string]any{"Id": strings.Repeat("e", 64), "Names": []string{"/service"}, "State": "running", "ImageID": fixtureImageID})
		},
		"short ID":               func(f *containerFixture) { f.list[0]["Id"] = "abc" },
		"multiple names":         func(f *containerFixture) { f.list[0]["Names"] = []string{"/service", "/alias"} },
		"no image ID":            func(f *containerFixture) { delete(f.list[0], "ImageID") },
		"inspect foreign ID":     func(f *containerFixture) { f.container["Id"] = strings.Repeat("e", 64) },
		"inspect foreign image":  func(f *containerFixture) { f.container["Image"] = fixtureOtherImage },
		"inspect foreign name":   func(f *containerFixture) { f.container["Name"] = "/foreign" },
		"missing state":          func(f *containerFixture) { delete(f.container, "State") },
		"paused":                 func(f *containerFixture) { f.container["State"].(map[string]any)["Paused"] = true },
		"restarting":             func(f *containerFixture) { f.container["State"].(map[string]any)["Restarting"] = true },
		"stopped":                func(f *containerFixture) { f.container["State"].(map[string]any)["Running"] = false },
		"missing start":          func(f *containerFixture) { delete(f.container["State"].(map[string]any), "StartedAt") },
		"missing restart count":  func(f *containerFixture) { delete(f.container, "RestartCount") },
		"wrong image inspect ID": func(f *containerFixture) { f.image["Id"] = fixtureOtherImage },
		"wrong platform":         func(f *containerFixture) { f.image["Architecture"] = "arm64" },
		"missing rootfs":         func(f *containerFixture) { delete(f.image, "RootFS") },
		"invalid layer": func(f *containerFixture) {
			f.image["RootFS"] = map[string]any{"Type": "layers", "Layers": []string{"approved:latest"}}
		},
		"missing manifest binding": func(f *containerFixture) {
			f.image["Descriptor"] = map[string]any{"digest": fixtureImageID, "mediaType": "application/vnd.oci.image.index.v1+json"}
		},
		"restart during sample": func(f *containerFixture) {
			f.change = func(path string, n int, v any) any {
				if strings.Contains(path, "/containers/") && !strings.HasSuffix(path, "/containers/json") && n == 2 {
					f.container["RestartCount"] = 1
				}
				return v
			}
		},
		"inventory disappears": func(f *containerFixture) {
			f.change = func(path string, n int, v any) any {
				if strings.HasSuffix(path, "/containers/json") && n == 2 {
					return []any{}
				}
				return v
			}
		},
		"partial count overflow": func(f *containerFixture) {
			for len(f.list) <= containerCountLimit {
				f.list = append(f.list, f.list[0])
			}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := newContainerFixture(t, "docker")
			change(f)
			requireContainerStatus(t, f, "error")
		})
	}
	for _, name := range []string{"missing namespace", "namespace changes"} {
		t.Run(name, func(t *testing.T) {
			f := newContainerFixture(t, "podman")
			if name == "missing namespace" {
				delete(f.container, "Namespace")
			} else {
				f.change = func(path string, n int, v any) any {
					if strings.Contains(path, "/containers/") && !strings.HasSuffix(path, "/containers/json") && n == 2 {
						f.container["Namespace"] = "foreign"
					}
					return v
				}
			}
			requireContainerStatus(t, f, "error")
		})
	}
}

func setupContainerManifest(f *containerFixture) {
	f.cfg.AllowedImages[0].Kind = "docker-manifest"
	f.cfg.AllowedImages[0].ManifestDigest = fixtureManifest
	f.container["ImageManifestDescriptor"] = map[string]any{"digest": fixtureManifest, "mediaType": "application/vnd.oci.image.manifest.v1+json", "platform": map[string]string{"os": "linux", "architecture": "amd64"}}
	f.image["Descriptor"] = map[string]any{"digest": fixtureImageID, "mediaType": "application/vnd.oci.image.index.v1+json"}
	f.raw = func(w http.ResponseWriter, r *http.Request, n int) bool {
		if !strings.Contains(r.URL.Path, "/images/") {
			return false
		}
		// Docker image-store names identify the parent index; its child
		// manifest is content, not necessarily an independently named image.
		if r.URL.Path != "/v1.49/images/"+fixtureImageID+"/json" {
			http.NotFound(w, r)
			return true
		}
		query := r.URL.Query()
		if len(query) == 0 {
			return false
		}
		var platform map[string]string
		if len(query) != 1 || len(query["platform"]) != 1 || json.Unmarshal([]byte(query.Get("platform")), &platform) != nil || len(platform) != 2 || platform["os"] != "linux" || platform["architecture"] != "amd64" {
			http.Error(w, "unsupported platform selector", 400)
			return true
		}
		var body any = map[string]any{"Id": fixtureManifest, "Descriptor": map[string]any{"digest": fixtureManifest, "mediaType": "application/vnd.oci.image.manifest.v1+json"}, "Os": "linux", "Architecture": "amd64", "RootFS": map[string]any{"Type": "layers", "Layers": []string{fixtureOtherImage}}}
		if f.change != nil {
			body = f.change(r.URL.RequestURI(), n, body)
		}
		_ = json.NewEncoder(w).Encode(body)
		return true
	}
}

func TestContainerDockerIndexManifestBinding(t *testing.T) {
	t.Run("valid index and actual manifest", func(t *testing.T) {
		f := newContainerFixture(t, "docker")
		setupContainerManifest(f)
		requireContainerStatus(t, f, "pass")
	})
	t.Run("wrong actual manifest policy", func(t *testing.T) {
		f := newContainerFixture(t, "docker")
		setupContainerManifest(f)
		f.cfg.AllowedImages[0].ManifestDigest = fixtureOtherImage
		requireContainerStatus(t, f, "drift")
	})
	t.Run("index mislabeled config", func(t *testing.T) {
		f := newContainerFixture(t, "docker")
		setupContainerManifest(f)
		f.cfg.AllowedImages[0].Kind = "docker-config-id"
		f.cfg.AllowedImages[0].ManifestDigest = ""
		requireContainerStatus(t, f, "drift")
	})
	t.Run("wrong actual platform", func(t *testing.T) {
		f := newContainerFixture(t, "docker")
		setupContainerManifest(f)
		f.container["ImageManifestDescriptor"].(map[string]any)["platform"] = map[string]string{"os": "linux", "architecture": "arm64"}
		requireContainerStatus(t, f, "error")
	})
	t.Run("partial actual manifest inspect", func(t *testing.T) {
		f := newContainerFixture(t, "docker")
		setupContainerManifest(f)
		f.change = func(path string, n int, v any) any {
			if strings.Contains(path, "?platform=") {
				return map[string]any{"Id": fixtureManifest, "Descriptor": map[string]any{"digest": fixtureManifest, "mediaType": "application/vnd.oci.image.manifest.v1+json"}}
			}
			return v
		}
		requireContainerStatus(t, f, "error")
	})
}

func TestContainerDockerPlatformResponseMustRemainBound(t *testing.T) {
	for _, failure := range []string{"ignored platform", "wrong platform config", "different manifest"} {
		t.Run(failure, func(t *testing.T) {
			f := newContainerFixture(t, "docker")
			setupContainerManifest(f)
			f.change = func(path string, n int, body any) any {
				if !strings.Contains(path, "?platform=") {
					return body
				}
				image := body.(map[string]any)
				switch failure {
				case "ignored platform":
					image["Id"] = fixtureImageID
				case "wrong platform config":
					image["Architecture"] = "arm64"
				case "different manifest":
					image["Id"] = fixtureOtherImage
					image["Descriptor"].(map[string]any)["digest"] = fixtureOtherImage
				}
				return image
			}
			requireContainerStatus(t, f, "error")
		})
	}
}

func TestContainerEndpointSourceBoundary(t *testing.T) {
	for name, change := range map[string]func(*containerFixture){
		"foreign daemon":            func(f *containerFixture) { f.info["ID"] = "foreign" },
		"foreign store":             func(f *containerFixture) { f.info["DockerRootDir"] = "/foreign" },
		"wrong rootless":            func(f *containerFixture) { f.info["SecurityOptions"] = []string{"name=rootless"} },
		"missing source field":      func(f *containerFixture) { delete(f.info, "SecurityOptions") },
		"foreign collector machine": func(f *containerFixture) { f.cfg.Source.MachineIDHash = strings.Repeat("0", 64) },
		"foreign peer":              func(f *containerFixture) { (*f.cfg.Source.PeerUID)++ },
		"version substitution":      func(f *containerFixture) { f.info["ServerVersion"] = "29.8.1" },
		"daemon changes": func(f *containerFixture) {
			f.change = func(path string, n int, v any) any {
				if strings.HasSuffix(path, "/info") && n == 2 {
					f.info["ID"] = "foreign"
				}
				return v
			}
		},
		"world writable socket": func(f *containerFixture) {
			if err := os.Chmod(f.cfg.Source.Socket, 0666); err != nil {
				t.Fatal(err)
			}
		},
		"socket symlink": func(f *containerFixture) {
			p := filepath.Join(f.dir, "link.sock")
			if err := os.Symlink(f.cfg.Source.Socket, p); err != nil {
				t.Fatal(err)
			}
			f.cfg.Source.Socket = p
		},
		"socket replaced": func(f *containerFixture) {
			f.change = func(path string, n int, v any) any {
				if strings.HasSuffix(path, "/containers/json") && n == 1 {
					if err := os.Rename(f.cfg.Source.Socket, filepath.Join(f.dir, "old.sock")); err != nil {
						t.Error(err)
					}
					if err := os.WriteFile(f.cfg.Source.Socket, []byte("replacement"), 0600); err != nil {
						t.Error(err)
					}
				}
				return v
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newContainerFixture(t, "docker")
			change(f)
			requireContainerStatus(t, f, "error")
		})
	}
	t.Run("environment cannot substitute command or source", func(t *testing.T) {
		f := newContainerFixture(t, "docker")
		for _, key := range []string{"DOCKER_HOST", "CONTAINER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "CONTAINER_CONNECTION"} {
			t.Setenv(key, "http://127.0.0.1:1/foreign")
		}
		t.Setenv("PATH", f.dir)
		if err := os.WriteFile(filepath.Join(f.dir, "docker"), []byte("#!/bin/sh\nexit 99\n"), 0700); err != nil {
			t.Fatal(err)
		}
		requireContainerStatus(t, f, "pass")
	})
	for _, field := range []string{"graphRoot", "runRoot", "graphDriverName"} {
		t.Run("Podman "+field, func(t *testing.T) {
			f := newContainerFixture(t, "podman")
			f.info["store"].(map[string]any)[field] = "/foreign"
			requireContainerStatus(t, f, "error")
		})
	}
}

func TestContainerMalformedAndBoundedResponses(t *testing.T) {
	bodies := map[string]string{
		"null inventory": "null", "object inventory": "{}", "trailing document": "[] []", "truncated inventory": "[{",
		"duplicate member": `[{"Id":"a","Id":"b"}]`, "case-equivalent member": `[{"Id":"a","ID":"b"}]`,
		"invalid UTF8": "[\xff]", "oversize": strings.Repeat(" ", containerResponseLimit+1),
		"nested beyond limit": strings.Repeat("[", 66) + strings.Repeat("]", 66),
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			f := newContainerFixture(t, "docker")
			f.raw = func(w http.ResponseWriter, r *http.Request, n int) bool {
				if strings.HasSuffix(r.URL.Path, "/containers/json") {
					_, _ = w.Write([]byte(body))
					return true
				}
				return false
			}
			requireContainerStatus(t, f, "error")
		})
	}
	for _, code := range []int{301, 403, 404, 500} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			f := newContainerFixture(t, "docker")
			f.raw = func(w http.ResponseWriter, r *http.Request, n int) bool {
				w.Header().Set("Location", "http://127.0.0.1:1/")
				w.WriteHeader(code)
				return true
			}
			requireContainerStatus(t, f, "error")
		})
	}
	t.Run("deadline", func(t *testing.T) {
		f := newContainerFixture(t, "docker")
		f.raw = func(w http.ResponseWriter, r *http.Request, n int) bool { <-r.Context().Done(); return true }
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		start := time.Now()
		got := collectContainerStateContext(ctx, f.cfg)
		if got.Status != "error" || time.Since(start) > time.Second {
			t.Fatalf("deadline failed: %+v", got)
		}
	})
	t.Run("aggregate bytes", func(t *testing.T) {
		f := newContainerFixture(t, "docker")
		payload := []byte(`{"padding":"` + strings.Repeat("x", containerResponseLimit-100) + `"}`)
		f.raw = func(w http.ResponseWriter, r *http.Request, n int) bool { _, _ = w.Write(payload); return true }
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		e, err := newContainerEndpoint(ctx, f.cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer e.transport.CloseIdleConnections()
		for n := 0; n < 17; n++ {
			var dst map[string]string
			err := e.get("/info", &dst)
			if n < 16 && err != nil {
				t.Fatalf("bounded response %d failed early: %v", n, err)
			}
			if n == 16 && err == nil {
				t.Fatal("aggregate response limit ignored")
			}
		}
	})
	t.Run("partial inspect failure", func(t *testing.T) {
		f := newContainerFixture(t, "docker")
		f.raw = func(w http.ResponseWriter, r *http.Request, n int) bool {
			if strings.Contains(r.URL.Path, "/images/") {
				http.Error(w, "fixture-secret-do-not-report", 500)
				return true
			}
			return false
		}
		requireContainerStatus(t, f, "error")
	})
}

func TestContainerPolicyMigrationAndValidation(t *testing.T) {
	for name, change := range map[string]func(*ContainerConfig){
		"old schema": func(c *ContainerConfig) { c.IdentitySchema = 0 }, "physical host scope": func(c *ContainerConfig) { c.Scope = "host" },
		"empty allowlist": func(c *ContainerConfig) { c.AllowedImages = nil }, "mutable identity": func(c *ContainerConfig) { c.AllowedImages[0].EngineImageID = "approved:latest" },
		"noncanonical digest": func(c *ContainerConfig) { c.AllowedImages[0].EngineImageID = strings.ToUpper(fixtureImageID) },
		"duplicate identity": func(c *ContainerConfig) {
			i := c.AllowedImages[0]
			i.Name = "other"
			c.AllowedImages = append(c.AllowedImages, i)
		},
		"duplicate service": func(c *ContainerConfig) { c.Required = append(c.Required, c.Required[0]) }, "unknown image": func(c *ContainerConfig) { c.Required[0].Image = "unknown" },
		"empty required conflict": func(c *ContainerConfig) { *c.AllowEmpty = true }, "implicit empty": func(c *ContainerConfig) { c.AllowEmpty = nil },
		"TCP source": func(c *ContainerConfig) { c.Source.Socket = "tcp://127.0.0.1:2375" }, "wrong adapter version": func(c *ContainerConfig) { c.Source.Version = "30.0.0" },
		"wrong identity kind": func(c *ContainerConfig) { c.AllowedImages[0].Kind = "podman-image-id-v5" },
		"missing manifest":    func(c *ContainerConfig) { c.AllowedImages[0].Kind = "docker-manifest" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newContainerFixture(t, "docker")
			change(&f.cfg)
			if err := validateContainerConfig(f.cfg); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
	for _, legacy := range []string{"[]", "null", "[approved:latest]"} {
		t.Run("legacy "+legacy, func(t *testing.T) {
			f := newContainerFixture(t, "docker")
			data, err := yaml.Marshal(f.cfg)
			if err != nil {
				t.Fatal(err)
			}
			var cfg ContainerConfig
			if err := yaml.Unmarshal(append(data, []byte("expected_images: "+legacy+"\n")...), &cfg); err == nil && validateContainerConfig(cfg) == nil {
				t.Fatal("legacy field accepted")
			}
		})
	}
}

func TestContainerScopeAndIdentityAreSigned(t *testing.T) {
	f := newContainerFixture(t, "docker")
	result := requireContainerStatus(t, f, "pass")
	report := generateReport(compare([]CollectorResult{result}))
	private, public := filepath.Join(f.dir, "private.key"), filepath.Join(f.dir, "public.key")
	if err := generateKeypair(private, public); err != nil {
		t.Fatal(err)
	}
	signed, err := signReport(report, private)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyReport(signed, public); err != nil {
		t.Fatal(err)
	}
	for i := range signed.Attestation.Collectors[0].Findings {
		original := signed.Attestation.Collectors[0].Findings[i].Actual
		signed.Attestation.Collectors[0].Findings[i].Actual = "substituted host or image"
		if err := verifyReport(signed, public); err == nil {
			t.Fatal("tampered source/image evidence verified")
		}
		signed.Attestation.Collectors[0].Findings[i].Actual = original
	}
	redacted := redactReport(report, PrivacyProfile{StripPaths: true, StripHostname: true})
	if !strings.Contains(redacted.Attestation.Collectors[0].Findings[0].Key, containerScope) || !strings.Contains(redacted.Attestation.Collectors[0].Findings[0].Detail, "does not authenticate daemon host") {
		t.Fatal("redaction erased scope limitation")
	}
}

func TestContainerPolicyFileTrustAndDefaultRemainFailClosed(t *testing.T) {
	f := newContainerFixture(t, "docker")
	p := AttestationPolicy{Version: 1, Attestation: AttestConfig{Collectors: CollectorToggle{Container: true}, Container: f.cfg}}
	data, err := yaml.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.dir, "policy.yaml")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := parsePolicyFile(path); err != nil {
		t.Fatalf("valid protected identity policy rejected: %v", err)
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := parsePolicyFile(path); err == nil {
		t.Fatal("untrusted writable identity policy accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, []byte("---\nversion: 1\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := parsePolicyFile(path); err == nil {
		t.Fatal("multiple identity policy documents accepted")
	}
	defaults, err := os.ReadFile("policies/default-policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var defaultPolicy AttestationPolicy
	if err := yaml.Unmarshal(defaults, &defaultPolicy); err != nil {
		t.Fatal(err)
	}
	if !defaultPolicy.Attestation.Collectors.Container || validatePolicy(defaultPolicy) == nil {
		t.Fatal("default collector disabled or incomplete trust baseline accepted")
	}
}

func TestContainerPartialInventoryCountAndBody(t *testing.T) {
	for _, runtime := range []string{"docker", "podman"} {
		t.Run(runtime, func(t *testing.T) {
			f := newContainerFixture(t, runtime)
			f.change = func(path string, n int, body any) any {
				if strings.HasSuffix(path, "/info") {
					if runtime == "docker" {
						f.info["ContainersRunning"] = 2
					} else {
						f.info["store"].(map[string]any)["containerStore"] = map[string]any{"running": 2}
					}
				}
				return body
			}
			requireContainerStatus(t, f, "error")
		})
	}
	t.Run("incomplete HTTP body", func(t *testing.T) {
		f := newContainerFixture(t, "docker")
		f.raw = func(w http.ResponseWriter, r *http.Request, n int) bool {
			w.Header().Set("Content-Length", "100")
			_, _ = w.Write([]byte("{}"))
			return true
		}
		requireContainerStatus(t, f, "error")
	})
}

func TestContainerUnicodeAliasAndRequiredRestartState(t *testing.T) {
	t.Run("Unicode status alias collision", func(t *testing.T) {
		f := newContainerFixture(t, "docker")
		f.container["State"].(map[string]any)["ſtatus"] = "running"
		requireContainerStatus(t, f, "error")
	})
	for _, runtime := range []string{"docker", "podman"} {
		for _, name := range []string{"missing", "null"} {
			t.Run(runtime+" Restarting "+name, func(t *testing.T) {
				f := newContainerFixture(t, runtime)
				state := f.container["State"].(map[string]any)
				if name == "missing" {
					delete(state, "Restarting")
				} else {
					state["Restarting"] = nil
				}
				requireContainerStatus(t, f, "error")
			})
		}
	}
}
