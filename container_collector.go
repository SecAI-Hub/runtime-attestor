package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"time"
)

type containerDescriptor struct {
	Digest    string                                      `json:"digest"`
	MediaType string                                      `json:"mediaType"`
	Platform  *struct{ OS, Architecture, Variant string } `json:"platform"`
}

type containerSummary struct {
	ID      string `json:"Id"`
	Names   []string
	State   string
	ImageID string
}

type containerSnapshot struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	ImageID      string `json:"engine_image_id"`
	Manifest     string `json:"manifest_digest,omitempty"`
	StartedAt    string `json:"started_at"`
	RestartCount int    `json:"restart_count"`
	Namespace    string `json:"podman_namespace,omitempty"`
}

func normalizeEngineImageID(runtime, id string) (string, error) {
	if runtime == "podman" && containerHex.MatchString(id) {
		id = "sha256:" + id
	}
	if !containerDigest.MatchString(id) {
		return "", fmt.Errorf("container image identity is not a complete sha256 digest")
	}
	return id, nil
}

func (e *containerEndpoint) list() ([]containerSummary, error) {
	var inventory []containerSummary
	if err := e.get("/containers/json?all=false", &inventory); err != nil {
		return nil, err
	}
	if inventory == nil || len(inventory) > containerCountLimit {
		return nil, fmt.Errorf("container inventory is null or exceeds count limit")
	}
	ids, names := map[string]bool{}, map[string]bool{}
	for index := range inventory {
		s := &inventory[index]
		if !containerHex.MatchString(s.ID) || ids[s.ID] || len(s.Names) != 1 || s.State != "running" {
			return nil, fmt.Errorf("container inventory has malformed, duplicate, ambiguous or non-running entries")
		}
		name := s.Names[0]
		if e.cfg.Runtime == "docker" {
			name = strings.TrimPrefix(name, "/")
		}
		if !containerName.MatchString(name) || names[name] {
			return nil, fmt.Errorf("container names are invalid or duplicated")
		}
		id, err := normalizeEngineImageID(e.cfg.Runtime, s.ImageID)
		if err != nil {
			return nil, err
		}
		s.Names = []string{name}
		s.ImageID = id
		ids[s.ID], names[name] = true, true
	}
	sort.Slice(inventory, func(i, j int) bool { return inventory[i].ID < inventory[j].ID })
	return inventory, nil
}

func (e *containerEndpoint) inspectContainer(s containerSummary) (containerSnapshot, error) {
	var c struct {
		ID           string `json:"Id"`
		Name, Image  string
		Namespace    *string
		RestartCount *int
		State        *struct {
			Status                string
			Running, Paused, Dead *bool
			Restarting            *bool
			StartedAt             string
		}
		ImageManifestDescriptor *containerDescriptor
	}
	if err := e.get("/containers/"+s.ID+"/json", &c); err != nil {
		return containerSnapshot{}, err
	}
	if c.ID != s.ID || c.State == nil || c.State.Running == nil || !*c.State.Running || c.State.Status != "running" || c.State.Paused == nil || *c.State.Paused || c.State.Dead == nil || *c.State.Dead || c.State.Restarting == nil || *c.State.Restarting || c.RestartCount == nil || *c.RestartCount < 0 {
		return containerSnapshot{}, fmt.Errorf("container inspect identity/state incomplete or changed")
	}
	started, err := time.Parse(time.RFC3339Nano, c.State.StartedAt)
	if err != nil || started.IsZero() {
		return containerSnapshot{}, fmt.Errorf("container start time is missing or invalid")
	}
	name := c.Name
	if e.cfg.Runtime == "docker" {
		name = strings.TrimPrefix(name, "/")
	}
	if name != s.Names[0] {
		return containerSnapshot{}, fmt.Errorf("container inspect name changed")
	}
	id, err := normalizeEngineImageID(e.cfg.Runtime, c.Image)
	if err != nil || id != s.ImageID {
		return containerSnapshot{}, fmt.Errorf("container inspect image identity changed or invalid")
	}
	snap := containerSnapshot{ID: c.ID, Name: name, ImageID: id, StartedAt: c.State.StartedAt, RestartCount: *c.RestartCount}
	if e.cfg.Runtime == "podman" {
		if c.Namespace == nil || len(*c.Namespace) > 128 || (*c.Namespace != "" && !containerName.MatchString(*c.Namespace)) || c.ImageManifestDescriptor != nil {
			return containerSnapshot{}, fmt.Errorf("Podman namespace/identity schema is invalid")
		}
		snap.Namespace = *c.Namespace
	} else if c.ImageManifestDescriptor != nil {
		if err := validateContainerManifest(c.ImageManifestDescriptor); err != nil {
			return containerSnapshot{}, err
		}
		snap.Manifest = c.ImageManifestDescriptor.Digest
	}
	return snap, nil
}

func validateContainerManifest(d *containerDescriptor) error {
	if d == nil || !containerDigest.MatchString(d.Digest) ||
		(d.MediaType != "application/vnd.oci.image.manifest.v1+json" && d.MediaType != "application/vnd.docker.distribution.manifest.v2+json") ||
		d.Platform == nil || d.Platform.OS != "linux" || d.Platform.Architecture != "amd64" || d.Platform.Variant != "" {
		return fmt.Errorf("actual image manifest/platform descriptor missing, invalid or unsupported")
	}
	return nil
}

type containerImageInspect struct {
	ID                        string `json:"Id"`
	Os, Architecture, Variant string
	Descriptor                *containerDescriptor
	RootFS                    *struct {
		Type   string
		Layers []string
	}
}

func (e *containerEndpoint) inspectImage(c containerSnapshot) (ContainerImage, error) {
	var image containerImageInspect
	if err := e.get("/images/"+c.ImageID+"/json", &image); err != nil {
		return ContainerImage{}, err
	}
	id, err := normalizeEngineImageID(e.cfg.Runtime, image.ID)
	if err != nil || id != c.ImageID {
		return ContainerImage{}, fmt.Errorf("image inspect ID does not match container image")
	}
	identity := ContainerImage{EngineImageID: id, Platform: "linux/amd64"}
	if e.cfg.Runtime == "podman" {
		identity.Kind = "podman-image-id-v5"
		if image.Descriptor != nil {
			return ContainerImage{}, fmt.Errorf("unsupported Podman image descriptor schema")
		}
	} else if c.Manifest == "" {
		identity.Kind = "docker-config-id"
		if image.Descriptor != nil {
			return ContainerImage{}, fmt.Errorf("multi-platform image has no actual container manifest binding")
		}
	} else {
		identity.Kind, identity.ManifestDigest = "docker-manifest", c.Manifest
		if image.Descriptor == nil || image.Descriptor.Digest != id {
			return ContainerImage{}, fmt.Errorf("Docker engine image target descriptor does not match ID")
		}
		switch image.Descriptor.MediaType {
		case "application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json", "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json":
		default:
			return ContainerImage{}, fmt.Errorf("unsupported Docker image target media type")
		}
		// A child manifest need not be an independently addressable image-store
		// name. Select the platform on the immutable engine object (API 1.49),
		// then require the returned target to equal the container's manifest.
		image = containerImageInspect{}
		selector := url.QueryEscape(`{"os":"linux","architecture":"amd64"}`)
		if err := e.get("/images/"+c.ImageID+"/json?platform="+selector, &image); err != nil {
			return ContainerImage{}, fmt.Errorf("Docker image platform inspect: %w", err)
		}
		if image.ID != c.Manifest || image.Descriptor == nil || image.Descriptor.Digest != c.Manifest {
			return ContainerImage{}, fmt.Errorf("actual Docker manifest inspect does not match container descriptor")
		}
		// Image target descriptors need not themselves include platform; the
		// container descriptor and actual image config independently supply it.
		if image.Descriptor.MediaType != "application/vnd.oci.image.manifest.v1+json" && image.Descriptor.MediaType != "application/vnd.docker.distribution.manifest.v2+json" {
			return ContainerImage{}, fmt.Errorf("actual Docker image is not a platform manifest")
		}
	}
	if image.Os != "linux" || image.Architecture != "amd64" || image.Variant != "" || image.RootFS == nil || image.RootFS.Type != "layers" || len(image.RootFS.Layers) > 128 {
		return ContainerImage{}, fmt.Errorf("image config platform/rootfs metadata missing or unsupported")
	}
	for _, layer := range image.RootFS.Layers {
		if !containerDigest.MatchString(layer) {
			return ContainerImage{}, fmt.Errorf("invalid rootfs layer digest")
		}
	}
	return identity, nil
}

func collectContainerState(cfg ContainerConfig) CollectorResult {
	ctx, cancel := context.WithTimeout(context.Background(), containerTimeout)
	defer cancel()
	return collectContainerStateContext(ctx, cfg)
}

func collectContainerStateContext(ctx context.Context, cfg ContainerConfig) CollectorResult {
	result := CollectorResult{Name: "container", Timestamp: time.Now().UTC().Format(time.RFC3339), Status: "error"}
	fail := func(err error) CollectorResult { result.Error = err.Error(); return result }
	if err := validateContainerConfig(cfg); err != nil {
		return fail(err)
	}
	e, err := newContainerEndpoint(ctx, cfg)
	if err != nil {
		return fail(err)
	}
	defer e.transport.CloseIdleConnections()
	beforeSource, err := e.sourceEvidence()
	if err != nil {
		return fail(err)
	}
	beforeList, err := e.list()
	if err != nil {
		return fail(err)
	}
	if len(beforeList) != beforeSource.RunningContainers {
		return fail(fmt.Errorf("inventory count disagrees with endpoint source count"))
	}
	snapshots := make([]containerSnapshot, 0, len(beforeList))
	identities := map[string]ContainerImage{}
	for _, c := range beforeList {
		snap, err := e.inspectContainer(c)
		if err != nil {
			return fail(err)
		}
		key := snap.ImageID + ":" + snap.Manifest
		if _, ok := identities[key]; !ok {
			if len(identities) >= containerCountLimit {
				return fail(fmt.Errorf("image identity count exceeds limit"))
			}
			i, err := e.inspectImage(snap)
			if err != nil {
				return fail(err)
			}
			identities[key] = i
		}
		snapshots = append(snapshots, snap)
	}
	for i, c := range beforeList {
		after, err := e.inspectContainer(c)
		if err != nil {
			return fail(err)
		}
		if after != snapshots[i] {
			return fail(fmt.Errorf("container changed during collection"))
		}
	}
	afterList, err := e.list()
	if err != nil {
		return fail(err)
	}
	if !reflect.DeepEqual(beforeList, afterList) {
		return fail(fmt.Errorf("container inventory changed during collection"))
	}
	afterSource, err := e.sourceEvidence()
	if err != nil {
		return fail(err)
	}
	if !reflect.DeepEqual(beforeSource, afterSource) {
		return fail(fmt.Errorf("container endpoint source changed during collection"))
	}
	if err := e.checkSocket(); err != nil {
		return fail(err)
	}
	if ctx.Err() != nil {
		return fail(fmt.Errorf("container collection deadline exceeded"))
	}
	sourceJSON, err := json.Marshal(afterSource)
	if err != nil {
		return fail(fmt.Errorf("cannot encode source evidence"))
	}
	result.Status = "pass"
	result.Findings = append(result.Findings, Finding{Key: "container_scope:endpoint-inventory", Actual: string(sourceJSON), Status: "pass", Detail: "Operator-selected endpoint inventory only; collector machine-id does not authenticate daemon host. Trusted daemon/peer may be a forwarder. No all-host, continuous, signer, writable-layer or layer-rehash claim."})
	required := map[string]string{}
	for _, s := range cfg.Required {
		required[s.Name] = s.Image
	}
	seen := map[string]bool{}
	for _, snap := range snapshots {
		actual := identities[snap.ImageID+":"+snap.Manifest]
		match := ""
		for _, image := range cfg.AllowedImages {
			candidate := image
			candidate.Name = ""
			if candidate == actual {
				match = image.Name
				break
			}
		}
		status, detail := "pass", "approved immutable engine image identity"
		if match == "" {
			status, detail = "fail", "unapproved immutable engine image identity"
		}
		if expected, ok := required[snap.Name]; ok {
			seen[snap.Name] = true
			if match != expected {
				status, detail = "fail", "required service image identity mismatch"
			}
		} else if cfg.DenyUnlisted {
			status, detail = "fail", "service name is outside the required service set"
		}
		if status == "fail" {
			result.Status = "drift"
		}
		evidence, _ := json.Marshal(struct {
			Container containerSnapshot `json:"container"`
			Identity  ContainerImage    `json:"identity"`
		}{snap, actual})
		result.Findings = append(result.Findings, Finding{Key: "container:" + snap.Name, Actual: string(evidence), Expected: required[snap.Name], Status: status, Detail: detail})
	}
	for _, s := range cfg.Required {
		if !seen[s.Name] {
			result.Status = "drift"
			result.Findings = append(result.Findings, Finding{Key: "required_container:" + s.Name, Expected: s.Image, Status: "fail", Detail: "required service is not running"})
		}
	}
	if len(snapshots) == 0 {
		status, detail := "pass", "empty endpoint inventory explicitly allowed"
		if !*cfg.AllowEmpty {
			result.Status, status, detail = "drift", "fail", "empty endpoint inventory is forbidden"
		}
		result.Findings = append(result.Findings, Finding{Key: "running_containers", Actual: "0", Status: status, Detail: detail})
	}
	return result
}
