package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Trust report types
// ---------------------------------------------------------------------------

// TrustReport is the signed attestation output.
type TrustReport struct {
	Version     string            `json:"version"`
	Hostname    string            `json:"hostname"`
	Attestation AttestationResult `json:"attestation"`
	Signature   string            `json:"signature,omitempty"`
	PublicKey   string            `json:"public_key,omitempty"`
	SignedAt    string            `json:"signed_at,omitempty"`
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------

// generateReport creates a trust report from an attestation result.
func generateReport(att AttestationResult) TrustReport {
	hostname, _ := os.Hostname()
	return TrustReport{
		Version:     "1",
		Hostname:    hostname,
		Attestation: att,
	}
}

// ---------------------------------------------------------------------------
// Ed25519 signing and verification
// ---------------------------------------------------------------------------

// signablePayload returns the canonical JSON bytes for signing.
// Excludes only the signature to prevent circular dependency. The signing
// timestamp and embedded informational public key remain authenticated.
func signablePayload(report TrustReport) ([]byte, error) {
	clean := report
	clean.Signature = ""
	return json.Marshal(clean)
}

// signReport signs the report with an ed25519 private key.
func signReport(report TrustReport, keyPath string) (TrustReport, error) {
	keyData, err := readOwnerOnlyFile(keyPath, 4096)
	if err != nil {
		return report, fmt.Errorf("read signing key: %w", err)
	}

	privBytes, err := base64.StdEncoding.DecodeString(string(keyData))
	if err != nil {
		return report, fmt.Errorf("decode signing key: %w", err)
	}

	if len(privBytes) != ed25519.PrivateKeySize {
		return report, fmt.Errorf("invalid key size: expected %d, got %d", ed25519.PrivateKeySize, len(privBytes))
	}

	privKey := ed25519.PrivateKey(privBytes)
	pubKey := privKey.Public().(ed25519.PublicKey)

	report.PublicKey = base64.StdEncoding.EncodeToString(pubKey)
	report.SignedAt = time.Now().UTC().Format(time.RFC3339Nano)
	payload, err := signablePayload(report)
	if err != nil {
		return report, fmt.Errorf("marshal payload: %w", err)
	}

	sig := ed25519.Sign(privKey, payload)

	report.Signature = base64.StdEncoding.EncodeToString(sig)
	return report, nil
}

// verifyReport verifies the signature on a trust report.
func verifyReport(report TrustReport, pubKeyPath string) error {
	if report.Signature == "" {
		return fmt.Errorf("report is unsigned")
	}
	if pubKeyPath == "" {
		return fmt.Errorf("trusted public key path is required; embedded keys are not trust anchors")
	}
	data, err := readBoundedRegularFile(pubKeyPath, 4096)
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}
	pubBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return fmt.Errorf("decode public key file: %w", err)
	}

	if len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size: expected %d, got %d", ed25519.PublicKeySize, len(pubBytes))
	}
	if report.PublicKey != "" && report.PublicKey != base64.StdEncoding.EncodeToString(pubBytes) {
		return fmt.Errorf("embedded public key does not match trusted public key")
	}
	if _, err := time.Parse(time.RFC3339Nano, report.SignedAt); err != nil {
		return fmt.Errorf("invalid signed_at timestamp")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(report.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	payload, err := signablePayload(report)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	if !ed25519.Verify(ed25519.PublicKey(pubBytes), payload, sigBytes) {
		return fmt.Errorf("signature verification failed — report may have been tampered with")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

// generateKeypair creates an ed25519 keypair and writes to files.
func generateKeypair(privPath, pubPath string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	privB64 := base64.StdEncoding.EncodeToString(priv)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	if err := writeNewKeyFile(privPath, []byte(privB64), 0600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := writeNewKeyFile(pubPath, []byte(pubB64), 0644); err != nil {
		return fmt.Errorf("write public key: %w (private key was created and must be secured)", err)
	}
	return nil
}

func writeNewKeyFile(path string, data []byte, mode os.FileMode) error {
	// #nosec G304 -- path is an explicit local CLI output; O_EXCL prevents overwriting an existing key file.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
