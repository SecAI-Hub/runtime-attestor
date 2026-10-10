package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGPUCapabilityDirectoryIsNotADeviceFailure(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nvidia-caps"), 0700); err != nil {
		t.Fatal(err)
	}
	if nodes, err := findGPUDevicesUnder(root); err != nil || len(nodes) != 0 {
		t.Fatalf("valid empty capability directory: %v %v", nodes, err)
	}
	if err := os.WriteFile(filepath.Join(root, "nvidia-caps", "nvidia-cap1"), []byte("not a device"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := findGPUDevicesUnder(root); err == nil {
		t.Fatal("ordinary capability file accepted as device")
	}
}

func TestGPUCapabilitySymlinkIsRejected(t *testing.T) {
	root := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "nvidia-caps")); err != nil {
		t.Fatal(err)
	}
	if _, err := findGPUDevicesUnder(root); err == nil {
		t.Fatal("symlink capability directory accepted")
	}
}

func TestMissingRequiredPolicyEvidenceFails(t *testing.T) {
	result := collectPolicyState(PolicyFilesConfig{Files: map[string]string{"required": filepath.Join(t.TempDir(), "missing.yaml")}})
	if result.Status != "fail" {
		t.Fatalf("missing required evidence yielded %s", result.Status)
	}
}

func TestPrivacyCoversServicePathsAndIPv6Listeners(t *testing.T) {
	profile := PrivacyProfile{StripPaths: true, StripListeners: true}
	got := redactString("artifact=/srv/private/model.gguf listener=[2001:db8::1]:8443", profile)
	if strings.Contains(got, "/srv/private") || strings.Contains(got, "2001:db8::1") {
		t.Fatalf("private evidence survived: %s", got)
	}
}
