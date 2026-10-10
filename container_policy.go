package main

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const containerScope = "endpoint-inventory"

// ContainerConfig requires deliberate enrollment. No field is learned from live
// containers. ExpectedImages exists solely to produce a useful migration error.
type ContainerConfig struct {
	IdentitySchema int                `yaml:"identity_schema"`
	Scope          string             `yaml:"scope"`
	Runtime        string             `yaml:"runtime"`
	ExpectedImages yaml.Node          `yaml:"expected_images,omitempty"`
	Source         ContainerSource    `yaml:"source"`
	AllowedImages  []ContainerImage   `yaml:"allowed_images"`
	Required       []ContainerService `yaml:"required_services"`
	AllowEmpty     *bool              `yaml:"allow_empty"`
	DenyUnlisted   bool               `yaml:"deny_unlisted_services"`
}

type ContainerSource struct {
	Socket        string  `yaml:"socket" json:"socket"`
	PeerUID       *uint32 `yaml:"peer_uid" json:"peer_uid"`
	MachineIDHash string  `yaml:"collector_machine_id_sha256" json:"collector_machine_id_sha256"`
	Version       string  `yaml:"version" json:"version"`
	StorageRoot   string  `yaml:"storage_root" json:"storage_root"`
	StorageDriver string  `yaml:"storage_driver" json:"storage_driver"`
	DaemonID      string  `yaml:"daemon_id" json:"daemon_id,omitempty"`
	RunRoot       string  `yaml:"run_root" json:"run_root,omitempty"`
	Rootless      *bool   `yaml:"rootless" json:"rootless"`
}

type ContainerImage struct {
	Name           string `yaml:"name" json:"name"`
	Kind           string `yaml:"kind" json:"kind"`
	EngineImageID  string `yaml:"engine_image_id" json:"engine_image_id"`
	ManifestDigest string `yaml:"manifest_digest" json:"manifest_digest,omitempty"`
	Platform       string `yaml:"platform" json:"platform"`
}

type ContainerService struct {
	Name  string `yaml:"name"`
	Image string `yaml:"image"`
}

var (
	containerHex    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	containerDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	containerName   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
)

func canonicalContainerPath(s string) bool {
	return filepath.IsAbs(s) && filepath.Clean(s) == s && len(s) <= 4096 && !strings.ContainsAny(s, "\x00\r\n")
}

func validateContainerConfig(c ContainerConfig) error {
	if c.IdentitySchema != 1 || c.ExpectedImages.Kind != 0 {
		return fmt.Errorf("identity_schema: 1 is required; remove legacy expected_images and enroll approved immutable allowed_images and source explicitly")
	}
	if c.Scope != containerScope {
		return fmt.Errorf("scope must be endpoint-inventory; physical host or all-namespace attestation is unsupported")
	}
	if c.Runtime != "docker" && c.Runtime != "podman" {
		return fmt.Errorf("runtime must be explicitly docker or podman")
	}
	s := c.Source
	if !canonicalContainerPath(s.Socket) || len(s.Socket) > 107 || s.PeerUID == nil ||
		!containerHex.MatchString(s.MachineIDHash) || !canonicalContainerPath(s.StorageRoot) ||
		!containerName.MatchString(s.StorageDriver) || s.Rootless == nil {
		return fmt.Errorf("source requires canonical Unix socket, peer_uid, collector_machine_id_sha256, storage_root, storage_driver and rootless")
	}
	if c.Runtime == "docker" {
		if s.Version != "29.8.0" || s.DaemonID == "" || len(s.DaemonID) > 256 || strings.ContainsAny(s.DaemonID, "\x00\r\n") || s.RunRoot != "" {
			return fmt.Errorf("Docker adapter requires version 29.8.0, daemon_id, and no run_root")
		}
	} else if s.Version != "5.8.4" || !canonicalContainerPath(s.RunRoot) || s.DaemonID != "" {
		return fmt.Errorf("Podman adapter requires version 5.8.4, run_root, and no daemon_id")
	}
	if c.AllowEmpty == nil || (*c.AllowEmpty && len(c.Required) != 0) {
		return fmt.Errorf("allow_empty must be explicit and cannot be true with required_services")
	}
	if len(c.AllowedImages) == 0 || len(c.AllowedImages) > 128 || len(c.Required) > 128 {
		return fmt.Errorf("configure 1..128 allowed_images and at most 128 required_services")
	}
	images := map[string]bool{}
	identities := map[string]bool{}
	for _, i := range c.AllowedImages {
		if !containerName.MatchString(i.Name) || images[i.Name] || !containerDigest.MatchString(i.EngineImageID) || i.Platform != "linux/amd64" {
			return fmt.Errorf("allowed_images require unique names, full sha256 engine_image_id and platform linux/amd64")
		}
		if c.Runtime == "docker" {
			if i.Kind != "docker-config-id" && i.Kind != "docker-manifest" {
				return fmt.Errorf("invalid Docker identity kind")
			}
		} else if i.Kind != "podman-image-id-v5" {
			return fmt.Errorf("invalid Podman identity kind")
		}
		if (i.Kind == "docker-manifest" && !containerDigest.MatchString(i.ManifestDigest)) ||
			(i.Kind != "docker-manifest" && i.ManifestDigest != "") {
			return fmt.Errorf("manifest_digest is required only for docker-manifest identity")
		}
		key := i.Kind + ":" + i.EngineImageID + ":" + i.ManifestDigest
		if identities[key] {
			return fmt.Errorf("duplicate allowed image identity")
		}
		identities[key], images[i.Name] = true, true
	}
	names := map[string]bool{}
	for _, s := range c.Required {
		if !containerName.MatchString(s.Name) || names[s.Name] || !images[s.Image] {
			return fmt.Errorf("required_services require unique exact names and an allowed image name")
		}
		names[s.Name] = true
	}
	return nil
}
