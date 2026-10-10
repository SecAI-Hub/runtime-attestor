package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	containerTimeout       = 10 * time.Second
	containerResponseLimit = 1 << 20
	containerTotalLimit    = 16 << 20
	containerCountLimit    = 128
)

// The source finding is part of the existing signed report payload. It describes
// endpoint scope, not physical daemon locality. Only selected non-secret fields
// are retained; never store or return raw inspect bodies/errors from the engine.
type containerSourceEvidence struct {
	PeerPIDAvailable  bool            `json:"peer_pid_available"`
	RunningContainers int             `json:"running_containers"`
	Scope             string          `json:"scope"`
	Runtime           string          `json:"runtime"`
	API               string          `json:"api"`
	Source            ContainerSource `json:"source"`
	PeerPID           int32           `json:"peer_pid"`
	PeerGID           uint32          `json:"peer_gid"`
}

type containerEndpoint struct {
	ctx        context.Context
	client     *http.Client
	transport  *http.Transport
	cfg        ContainerConfig
	api        string
	socketInfo os.FileInfo
	peer       *containerPeer
	total      int
}

func newContainerEndpoint(ctx context.Context, cfg ContainerConfig) (*containerEndpoint, error) {
	e := &containerEndpoint{ctx: ctx, cfg: cfg, api: "/v1.49"}
	if cfg.Runtime == "podman" {
		e.api = "/v5.8.4/libpod"
	}
	if err := e.checkSocket(); err != nil {
		return nil, err
	}
	e.transport = &http.Transport{
		Proxy: nil, DisableCompression: true, MaxConnsPerHost: 1,
		MaxResponseHeaderBytes: 32 << 10,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "container-endpoint:80" {
				return nil, fmt.Errorf("unexpected transport destination")
			}
			if err := e.checkSocket(); err != nil {
				return nil, err
			}
			conn, err := (&net.Dialer{}).DialContext(ctx, "unix", cfg.Source.Socket)
			if err != nil {
				return nil, fmt.Errorf("cannot connect to configured container socket")
			}
			peer, err := readContainerPeer(conn)
			if err != nil || peer.UID != *cfg.Source.PeerUID || peer.PID < 0 {
				conn.Close()
				return nil, fmt.Errorf("container endpoint peer credentials mismatch or unavailable")
			}
			if e.peer != nil && *e.peer != peer {
				conn.Close()
				return nil, fmt.Errorf("container endpoint peer changed")
			}
			e.peer = &peer
			if err := e.checkSocket(); err != nil {
				conn.Close()
				return nil, err
			}
			return conn, nil
		},
	}
	e.client = &http.Client{Transport: e.transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return fmt.Errorf("container endpoint redirects are forbidden")
	}}
	return e, nil
}

func (e *containerEndpoint) checkSocket() error {
	p := e.cfg.Source.Socket
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil || resolved != p {
		return fmt.Errorf("container socket must exist at its canonical path without symlinks")
	}
	info, err := os.Lstat(p)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0002 != 0 || !containerSocketOwner(info, *e.cfg.Source.PeerUID) {
		return fmt.Errorf("container socket type, ownership or permissions are invalid")
	}
	if e.socketInfo != nil && (!os.SameFile(e.socketInfo, info) || e.socketInfo.Mode() != info.Mode()) {
		return fmt.Errorf("container socket changed during collection")
	}
	e.socketInfo = info
	return nil
}

func (e *containerEndpoint) get(path string, dst any) error {
	if err := e.ctx.Err(); err != nil {
		return fmt.Errorf("container collection deadline exceeded")
	}
	req, err := http.NewRequestWithContext(e.ctx, http.MethodGet, "http://container-endpoint"+e.api+path, nil)
	if err != nil {
		return fmt.Errorf("invalid container API request")
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("container API request failed or timed out")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Encoding") != "" {
		return fmt.Errorf("container API returned an unsuccessful or encoded response")
	}
	limit := containerResponseLimit
	if remaining := containerTotalLimit - e.total; remaining < limit {
		limit = remaining
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	e.total += len(data)
	if err != nil || len(data) > limit {
		return fmt.Errorf("container API response incomplete or exceeds byte limits")
	}
	if err := strictContainerJSON(data, dst); err != nil {
		return fmt.Errorf("container API JSON is malformed, ambiguous or has an invalid schema")
	}
	return nil
}

// Reject duplicate (including case-equivalent) members, trailing values, invalid
// UTF-8 and excessive nesting before Go's case-insensitive struct decoding.
func strictContainerJSON(data []byte, dst any) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 64 {
			return fmt.Errorf("JSON nesting limit")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok {
					return fmt.Errorf("invalid member")
				}
				name = foldContainerJSONKey(name)
				if seen[name] {
					return fmt.Errorf("duplicate member")
				}
				seen[name] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("invalid delimiter")
		}
		_, err = d.Token()
		return err
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return json.Unmarshal(data, dst)
}

// Use the same Unicode simple-fold equivalence as encoding/json, including
// long-s and Kelvin sign. A hash map of canonical keys avoids pairwise scans.
func foldContainerJSONKey(key string) string {
	var result strings.Builder
	result.Grow(len(key))
	for _, r := range key {
		smallest := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < smallest {
				smallest = next
			}
		}
		result.WriteRune(smallest)
	}
	return result.String()
}

func collectorMachineHash() (string, error) {
	data, err := readTrustedConfigFile("/etc/machine-id", 4096)
	if err != nil {
		return "", fmt.Errorf("collector machine-id is unavailable or untrusted")
	}
	if decoded, decodeErr := hex.DecodeString(strings.TrimSpace(string(data))); decodeErr != nil || len(decoded) != 16 {
		return "", fmt.Errorf("invalid collector machine-id")
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func (e *containerEndpoint) sourceEvidence() (containerSourceEvidence, error) {
	if err := e.checkSocket(); err != nil {
		return containerSourceEvidence{}, err
	}
	machine, err := collectorMachineHash()
	if err != nil || machine != e.cfg.Source.MachineIDHash {
		return containerSourceEvidence{}, fmt.Errorf("collector machine-id does not match policy")
	}
	s := e.cfg.Source
	var running *int
	if e.cfg.Runtime == "docker" {
		var v struct{ Version, Os, Arch string }
		if err := e.get("/version", &v); err != nil {
			return containerSourceEvidence{}, err
		}
		var info struct {
			ContainersRunning *int

			ID, DockerRootDir, Driver, ServerVersion, OSType, Architecture string
			SecurityOptions                                                []string
		}
		if err := e.get("/info", &info); err != nil {
			return containerSourceEvidence{}, err
		}
		running = info.ContainersRunning
		rootless := false
		for _, option := range info.SecurityOptions {
			if option == "name=rootless" {
				rootless = true
			}
		}
		if v.Version != s.Version || v.Os != "linux" || v.Arch != "amd64" || info.ServerVersion != s.Version || info.ID != s.DaemonID || info.DockerRootDir != s.StorageRoot || info.Driver != s.StorageDriver || info.OSType != "linux" || (info.Architecture != "x86_64" && info.Architecture != "amd64") || rootless != *s.Rootless || info.SecurityOptions == nil {
			return containerSourceEvidence{}, fmt.Errorf("Docker endpoint identity does not match policy")
		}
	} else {
		var info struct {
			Version struct{ Version string }
			Host    struct {
				OS, Arch string
				Security struct{ Rootless *bool }
			}
			Store struct {
				GraphRoot, RunRoot, GraphDriverName string
				ContainerStore                      struct{ Running *int }
			}
		}
		if err := e.get("/info", &info); err != nil {
			return containerSourceEvidence{}, err
		}
		running = info.Store.ContainerStore.Running
		if info.Version.Version != s.Version || info.Host.OS != "linux" || info.Host.Arch != "amd64" || info.Host.Security.Rootless == nil || *info.Host.Security.Rootless != *s.Rootless || info.Store.GraphRoot != s.StorageRoot || info.Store.RunRoot != s.RunRoot || info.Store.GraphDriverName != s.StorageDriver {
			return containerSourceEvidence{}, fmt.Errorf("Podman endpoint identity does not match policy")
		}
	}
	if running == nil || *running < 0 || *running > containerCountLimit {
		return containerSourceEvidence{}, fmt.Errorf("source running container count missing or exceeds limits")
	}
	if e.peer == nil {
		return containerSourceEvidence{}, fmt.Errorf("container peer identity unavailable")
	}
	return containerSourceEvidence{PeerPIDAvailable: e.peer.PID > 0, RunningContainers: *running, Scope: containerScope, Runtime: e.cfg.Runtime, API: e.api, Source: s, PeerPID: e.peer.PID, PeerGID: e.peer.GID}, nil
}
