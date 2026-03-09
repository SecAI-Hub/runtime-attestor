package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func setupTestPolicy() {
	policyMu.Lock()
	policy = AttestationPolicy{
		Version: 1,
		Attestation: AttestConfig{
			Collectors: CollectorToggle{
				Model:     true,
				Container: true,
				Network:   true,
				Mount:     true,
				GPU:       true,
				Policy:    true,
			},
			Model: ModelConfig{
				VaultDir:       "/nonexistent",
				AllowedFormats: []string{"gguf"},
			},
			Network: NetworkConfig{
				AllowedListeners:        []string{"127.0.0.1:8470"},
				DenyUnexpectedListeners: true,
			},
			RateLimit: RateLimitConfig{RequestsPerMinute: 100},
		},
	}
	policyMu.Unlock()
	serviceToken = ""
}

// writeTestFile creates a temp file with given content and returns its path.
func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// ---------------------------------------------------------------------------
// Health endpoint tests
// ---------------------------------------------------------------------------

func TestHealthEndpoint(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp["service"] != "runtime-attestor" {
		t.Fatalf("unexpected service: %s", resp["service"])
	}
}

// ---------------------------------------------------------------------------
// Model collector tests
// ---------------------------------------------------------------------------

func TestModelCollector_EmptyVault(t *testing.T) {
	dir := t.TempDir()
	cfg := ModelConfig{
		VaultDir:       dir,
		AllowedFormats: []string{"gguf"},
	}

	result := collectModelState(cfg)
	if result.Status != "pass" {
		t.Fatalf("expected pass for empty vault, got %s", result.Status)
	}
}

func TestModelCollector_NoVaultDir(t *testing.T) {
	cfg := ModelConfig{VaultDir: ""}
	result := collectModelState(cfg)
	if result.Status != "skipped" {
		t.Fatalf("expected skipped, got %s", result.Status)
	}
}

func TestModelCollector_HashMismatch(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "test-model.gguf", "model-data-here")

	// Start a mock registry that returns a different hash.
	mockRegistry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"models": []map[string]string{
				{
					"name":     "test-model",
					"format":   "gguf",
					"filename": "test-model.gguf",
					"sha256":   "0000000000000000000000000000000000000000000000000000000000000000",
				},
			},
		})
	}))
	defer mockRegistry.Close()

	cfg := ModelConfig{
		VaultDir:       dir,
		RegistryURL:    mockRegistry.URL,
		AllowedFormats: []string{"gguf"},
	}

	result := collectModelState(cfg)
	if result.Status == "pass" {
		t.Fatal("expected drift or fail for hash mismatch, got pass")
	}

	found := false
	for _, f := range result.Findings {
		if f.Key == "test-model.gguf" && (f.Status == "fail" || f.Status == "drift") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected finding for test-model.gguf hash mismatch")
	}
}

func TestModelCollector_HashMatch(t *testing.T) {
	dir := t.TempDir()
	content := "trusted-model-content"
	writeTestFile(t, dir, "good-model.gguf", content)

	// Compute expected hash.
	h := sha256.Sum256([]byte(content))
	expected := hex.EncodeToString(h[:])

	mockRegistry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"models": []map[string]string{
				{
					"name":     "good-model",
					"format":   "gguf",
					"filename": "good-model.gguf",
					"sha256":   expected,
				},
			},
		})
	}))
	defer mockRegistry.Close()

	cfg := ModelConfig{
		VaultDir:       dir,
		RegistryURL:    mockRegistry.URL,
		AllowedFormats: []string{"gguf"},
	}

	result := collectModelState(cfg)
	if result.Status != "pass" {
		t.Fatalf("expected pass, got %s", result.Status)
	}
}

func TestModelCollector_UnknownModel(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "rogue-model.gguf", "rogue-data")

	// Registry returns empty list.
	mockRegistry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"models": []map[string]string{}})
	}))
	defer mockRegistry.Close()

	cfg := ModelConfig{
		VaultDir:       dir,
		RegistryURL:    mockRegistry.URL,
		AllowedFormats: []string{"gguf"},
	}

	result := collectModelState(cfg)
	if result.Status != "drift" {
		t.Fatalf("expected drift for unknown model, got %s", result.Status)
	}
}

// ---------------------------------------------------------------------------
// Policy collector tests
// ---------------------------------------------------------------------------

func TestPolicyCollector_HashMatch(t *testing.T) {
	dir := t.TempDir()
	content := "version: 1\ntools:\n  default: deny\n"
	path := writeTestFile(t, dir, "fw.yaml", content)

	h := sha256.Sum256([]byte(content))
	expected := hex.EncodeToString(h[:])

	cfg := PolicyFilesConfig{
		Files:          map[string]string{"tool-firewall": path},
		ApprovedHashes: map[string]string{"tool-firewall": expected},
	}

	result := collectPolicyState(cfg)
	if result.Status != "pass" {
		t.Fatalf("expected pass, got %s", result.Status)
	}
}

func TestPolicyCollector_HashDrift(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "fw.yaml", "changed-content")

	cfg := PolicyFilesConfig{
		Files:          map[string]string{"tool-firewall": filepath.Join(dir, "fw.yaml")},
		ApprovedHashes: map[string]string{"tool-firewall": "wrong-hash"},
	}

	result := collectPolicyState(cfg)
	if result.Status != "drift" {
		t.Fatalf("expected drift, got %s", result.Status)
	}
}

func TestPolicyCollector_MissingFile(t *testing.T) {
	cfg := PolicyFilesConfig{
		Files:          map[string]string{"missing": "/nonexistent/policy.yaml"},
		ApprovedHashes: map[string]string{},
	}

	result := collectPolicyState(cfg)
	// Should report error for the missing file but not crash.
	found := false
	for _, f := range result.Findings {
		if f.Status == "error" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected error finding for missing file")
	}
}

// ---------------------------------------------------------------------------
// Comparison engine tests
// ---------------------------------------------------------------------------

func TestCompare_AllPass(t *testing.T) {
	results := []CollectorResult{
		{Name: "a", Status: "pass"},
		{Name: "b", Status: "pass"},
	}

	att := compare(results)
	if att.Verdict != "pass" {
		t.Fatalf("expected pass, got %s", att.Verdict)
	}
	if att.Score != 1.0 {
		t.Fatalf("expected score 1.0, got %.2f", att.Score)
	}
}

func TestCompare_Drift(t *testing.T) {
	results := []CollectorResult{
		{Name: "a", Status: "pass"},
		{Name: "b", Status: "drift"},
	}

	att := compare(results)
	if att.Verdict != "drift" {
		t.Fatalf("expected drift, got %s", att.Verdict)
	}
	if att.Score != 0.75 {
		t.Fatalf("expected score 0.75, got %.2f", att.Score)
	}
}

func TestCompare_Fail(t *testing.T) {
	results := []CollectorResult{
		{Name: "a", Status: "pass", Findings: []Finding{{Status: "fail"}}},
		{Name: "b", Status: "pass"},
	}

	att := compare(results)
	if att.Verdict != "fail" {
		t.Fatalf("expected fail, got %s", att.Verdict)
	}
}

func TestCompare_SkippedIgnored(t *testing.T) {
	results := []CollectorResult{
		{Name: "a", Status: "pass"},
		{Name: "b", Status: "skipped"},
	}

	att := compare(results)
	if att.Verdict != "pass" {
		t.Fatalf("expected pass (skipped ignored), got %s", att.Verdict)
	}
	if att.Score != 1.0 {
		t.Fatalf("expected score 1.0, got %.2f", att.Score)
	}
}

func TestCompare_AllSkipped(t *testing.T) {
	results := []CollectorResult{
		{Name: "a", Status: "skipped"},
	}

	att := compare(results)
	if att.Score != 1.0 {
		t.Fatalf("expected 1.0 for all-skipped, got %.2f", att.Score)
	}
}

// ---------------------------------------------------------------------------
// Report generation and signing tests
// ---------------------------------------------------------------------------

func TestGenerateReport(t *testing.T) {
	att := AttestationResult{Verdict: "pass", Score: 1.0}
	report := generateReport(att)

	if report.Version != "1" {
		t.Fatalf("expected version 1, got %s", report.Version)
	}
	if report.Attestation.Verdict != "pass" {
		t.Fatalf("expected pass, got %s", report.Attestation.Verdict)
	}
}

func TestSignAndVerify(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "test.key")
	pubPath := filepath.Join(dir, "test.pub")

	if err := generateKeypair(privPath, pubPath); err != nil {
		t.Fatalf("keygen: %v", err)
	}

	att := AttestationResult{Verdict: "pass", Score: 1.0}
	report := generateReport(att)

	signed, err := signReport(report, privPath)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if signed.Signature == "" {
		t.Fatal("expected signature")
	}
	if signed.PublicKey == "" {
		t.Fatal("expected public key")
	}

	// Verify with embedded key.
	if err := verifyReport(signed, ""); err != nil {
		t.Fatalf("verify with embedded key: %v", err)
	}

	// Verify with explicit key file.
	if err := verifyReport(signed, pubPath); err != nil {
		t.Fatalf("verify with key file: %v", err)
	}
}

func TestVerify_Tampered(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "test.key")
	pubPath := filepath.Join(dir, "test.pub")
	generateKeypair(privPath, pubPath)

	att := AttestationResult{Verdict: "pass", Score: 1.0}
	report := generateReport(att)
	signed, _ := signReport(report, privPath)

	// Tamper with the report.
	signed.Attestation.Verdict = "fail"

	err := verifyReport(signed, pubPath)
	if err == nil {
		t.Fatal("expected verification to fail on tampered report")
	}
}

// ---------------------------------------------------------------------------
// HTTP handler tests
// ---------------------------------------------------------------------------

func TestAttestEndpoint(t *testing.T) {
	setupTestPolicy()

	req := httptest.NewRequest(http.MethodGet, "/v1/attest", nil)
	w := httptest.NewRecorder()
	handleAttest(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var report TrustReport
	if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if report.Version != "1" {
		t.Fatalf("expected version 1, got %s", report.Version)
	}
}

func TestAttestEndpoint_WrongMethod(t *testing.T) {
	req := httptest.NewRequest(http.MethodDelete, "/v1/attest", nil)
	w := httptest.NewRecorder()
	handleAttest(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestLatestReport_Empty(t *testing.T) {
	latestReportMu.Lock()
	latestReport = nil
	latestReportMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/v1/report/latest", nil)
	w := httptest.NewRecorder()
	handleLatestReport(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestReloadEndpoint_RequiresPost(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/reload", nil)
	w := httptest.NewRecorder()
	handleReload(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/metrics", nil)
	w := httptest.NewRecorder()
	handleMetrics(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var metrics map[string]int64
	if err := json.Unmarshal(w.Body.Bytes(), &metrics); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Service token auth tests
// ---------------------------------------------------------------------------

func TestServiceToken_DevMode(t *testing.T) {
	serviceToken = ""
	called := false
	handler := requireServiceToken(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/reload", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Fatal("handler should be called in dev mode")
	}
}

func TestServiceToken_ValidToken(t *testing.T) {
	serviceToken = "test-secret-token"
	called := false
	handler := requireServiceToken(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/reload", nil)
	req.Header.Set("Authorization", "Bearer test-secret-token")
	w := httptest.NewRecorder()
	handler(w, req)

	if !called {
		t.Fatal("handler should be called with valid token")
	}
	serviceToken = ""
}

func TestServiceToken_InvalidToken(t *testing.T) {
	serviceToken = "test-secret-token"
	handler := requireServiceToken(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/reload", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	serviceToken = ""
}

// ---------------------------------------------------------------------------
// Mount collector tests
// ---------------------------------------------------------------------------

func TestMountCollector_NoExpected(t *testing.T) {
	cfg := MountConfig{Expected: nil}
	result := collectMountState(cfg)
	if result.Status != "skipped" {
		t.Fatalf("expected skipped, got %s", result.Status)
	}
}

// ---------------------------------------------------------------------------
// GPU collector tests
// ---------------------------------------------------------------------------

func TestGPUCollector_NoDevices(t *testing.T) {
	cfg := GPUConfig{
		AllowedDevices:        []string{"/dev/nvidia0"},
		DenyUnexpectedDevices: true,
	}
	result := collectGPUState(cfg)
	// On macOS/CI there are typically no NVIDIA devices.
	if result.Status != "pass" && result.Status != "drift" {
		t.Fatalf("expected pass or drift, got %s", result.Status)
	}
}

// ---------------------------------------------------------------------------
// SHA256 helper test
// ---------------------------------------------------------------------------

func TestSHA256File(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, "test.bin", "hello world")

	hash, err := sha256File(path)
	if err != nil {
		t.Fatal(err)
	}

	expected := sha256.Sum256([]byte("hello world"))
	expectedHex := hex.EncodeToString(expected[:])

	if hash != expectedHex {
		t.Fatalf("expected %s, got %s", expectedHex, hash)
	}
}
