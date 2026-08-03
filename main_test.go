package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func setupTestPolicy() {
	auditRequired.Store(false)
	auditHealthy.Store(false)
	persistReports.Store(false)
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

func TestHealthEndpoint_NoAuthRequired(t *testing.T) {
	serviceToken = "secret"
	defer func() { serviceToken = "" }()

	mux := buildMux()
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/health", nil))
	if w.Code != 200 {
		t.Errorf("health should not require auth, got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// Model collector tests
// ---------------------------------------------------------------------------

func TestModelCollector_EmptyVault(t *testing.T) {
	dir := t.TempDir()
	mockRegistry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"models": []any{}})
	}))
	defer mockRegistry.Close()
	cfg := ModelConfig{
		VaultDir:       dir,
		RegistryURL:    mockRegistry.URL,
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
// Filesystem hardening tests
// ---------------------------------------------------------------------------

func TestHashModelFiles_RejectsSymlinks(t *testing.T) {
	dir := t.TempDir()
	real := writeTestFile(t, dir, "real.gguf", "data")
	if err := os.Symlink(real, filepath.Join(dir, "link.gguf")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	results, err := hashModelFiles(dir, []string{"gguf"}, 0)
	if err == nil || results != nil {
		t.Fatal("matching symlink must make collection fail closed")
	}
}

func TestHashModelFiles_RejectsOversized(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "small.gguf", "ok")
	writeTestFile(t, dir, "big.gguf", strings.Repeat("x", 200))

	results, err := hashModelFiles(dir, []string{"gguf"}, 100)
	if err == nil || results != nil {
		t.Fatal("oversized matching model must make collection fail closed")
	}
}

// ---------------------------------------------------------------------------
// Registry hardening tests
// ---------------------------------------------------------------------------

func TestFetchRegistry_InvalidScheme(t *testing.T) {
	_, err := fetchRegistryManifest("ftp://evil.host", "")
	if err == nil {
		t.Fatal("expected error for non-http scheme")
	}
	if !strings.Contains(err.Error(), "http or https") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestFetchRegistry_AuthHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"models": []interface{}{}})
	}))
	defer srv.Close()

	os.Setenv("TEST_REG_TOKEN", "my-secret")
	defer os.Unsetenv("TEST_REG_TOKEN")

	_, err := fetchRegistryManifest(srv.URL, "TEST_REG_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer my-secret" {
		t.Errorf("expected auth header, got %q", gotAuth)
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

func TestPolicyCollector_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := writeTestFile(t, dir, "real.yaml", "content")
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	cfg := PolicyFilesConfig{
		Files:          map[string]string{"linked": link},
		ApprovedHashes: map[string]string{},
	}

	result := collectPolicyState(cfg)
	found := false
	for _, f := range result.Findings {
		if f.Key == "linked" && f.Status == "fail" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected fail finding for symlink policy file")
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

func TestCompare_SkippedFailsClosed(t *testing.T) {
	results := []CollectorResult{
		{Name: "a", Status: "pass"},
		{Name: "b", Status: "skipped"},
	}

	att := compare(results)
	if att.Verdict != "fail" {
		t.Fatalf("expected fail for missing evidence, got %s", att.Verdict)
	}
	if att.Score != 0.5 {
		t.Fatalf("expected score 0.5, got %.2f", att.Score)
	}
}

func TestCompare_AllSkipped(t *testing.T) {
	results := []CollectorResult{
		{Name: "a", Status: "skipped"},
	}

	att := compare(results)
	if att.Score != 0.0 || att.Verdict != "fail" {
		t.Fatalf("expected fail/0.0 for all-skipped, got %s/%.2f", att.Verdict, att.Score)
	}
}

func TestCompare_CriticalCollectorError_IsFail(t *testing.T) {
	results := []CollectorResult{
		{Name: "model", Status: "error", Error: "vault missing"},
		{Name: "network", Status: "pass"},
	}

	att := compare(results)
	if att.Verdict != "fail" {
		t.Fatalf("expected fail for critical collector error, got %s", att.Verdict)
	}
}

func TestCompare_NonCriticalError_IsFailClosed(t *testing.T) {
	results := []CollectorResult{
		{Name: "container", Status: "error", Error: "podman missing"},
		{Name: "network", Status: "pass"},
	}

	att := compare(results)
	if att.Verdict != "fail" {
		t.Fatalf("expected fail for unavailable evidence, got %s", att.Verdict)
	}
}

func TestCompare_PolicyError_IsFail(t *testing.T) {
	results := []CollectorResult{
		{Name: "policy", Status: "error", Error: "cannot hash"},
		{Name: "network", Status: "pass"},
	}

	att := compare(results)
	if att.Verdict != "fail" {
		t.Fatalf("expected fail for policy collector error, got %s", att.Verdict)
	}
}

// ---------------------------------------------------------------------------
// Redaction tests
// ---------------------------------------------------------------------------

func TestRedactReport_Hostname(t *testing.T) {
	report := TrustReport{
		Hostname:    "build-server-01",
		Attestation: AttestationResult{Verdict: "pass"},
	}

	redacted := redactReport(report, PrivacyProfile{StripHostname: true})
	if redacted.Hostname != "[REDACTED]" {
		t.Errorf("expected hostname redacted, got %s", redacted.Hostname)
	}
}

func TestRedactReport_Paths(t *testing.T) {
	report := TrustReport{
		Attestation: AttestationResult{
			Collectors: []CollectorResult{{
				Name:   "policy",
				Status: "drift",
				Findings: []Finding{{
					Key:    "/etc/secure-ai/policy/fw.yaml",
					Detail: "file at /home/user/policies/fw.yaml changed",
					Status: "drift",
				}},
			}},
		},
	}

	redacted := redactReport(report, PrivacyProfile{StripPaths: true})
	f := redacted.Attestation.Collectors[0].Findings[0]
	if strings.Contains(f.Detail, "/home/user") {
		t.Error("path should be redacted from detail")
	}
}

func TestRedactReport_Listeners(t *testing.T) {
	report := TrustReport{
		Attestation: AttestationResult{
			Collectors: []CollectorResult{{
				Name:   "network",
				Status: "pass",
				Findings: []Finding{{
					Key:    "127.0.0.1:8470",
					Status: "pass",
					Detail: "expected listener",
				}},
			}},
		},
	}

	redacted := redactReport(report, PrivacyProfile{StripListeners: true})
	f := redacted.Attestation.Collectors[0].Findings[0]
	if f.Key != "[REDACTED:listener]" {
		t.Errorf("listener key should be redacted, got %s", f.Key)
	}
}

func TestRedactReport_DoesNotMutateOriginal(t *testing.T) {
	report := TrustReport{
		Hostname:    "original-host",
		Attestation: AttestationResult{Verdict: "pass"},
	}

	redactReport(report, PrivacyProfile{StripHostname: true})
	if report.Hostname != "original-host" {
		t.Error("original report should not be mutated")
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

	if err := verifyReport(signed, ""); err == nil {
		t.Fatal("embedded key must not be accepted as a trust anchor")
	}

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

	signed.Attestation.Verdict = "fail"

	err := verifyReport(signed, pubPath)
	if err == nil {
		t.Fatal("expected verification to fail on tampered report")
	}
}

func TestGenerateKeypairRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "test.key")
	pubPath := filepath.Join(dir, "test.pub")
	if err := generateKeypair(privPath, pubPath); err != nil {
		t.Fatalf("first keygen: %v", err)
	}
	before, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := generateKeypair(privPath, filepath.Join(dir, "second.pub")); err == nil {
		t.Fatal("key generation must not overwrite an existing private key")
	}
	after, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("existing private key changed")
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

func TestAllEndpointsRequireAuth(t *testing.T) {
	serviceToken = "test-secret"
	defer func() { serviceToken = "" }()

	mux := buildMux()

	endpoints := []struct {
		method string
		path   string
	}{
		{"GET", "/v1/attest"},
		{"GET", "/v1/report/latest"},
		{"POST", "/v1/reload"},
		{"GET", "/v1/metrics"},
	}

	for _, ep := range endpoints {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(ep.method, ep.path, nil))
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s: expected 403 without token, got %d", ep.method, ep.path, w.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// Service token auth tests
// ---------------------------------------------------------------------------

func TestServiceToken_MissingFailsClosed(t *testing.T) {
	serviceToken = ""
	called := false
	handler := requireServiceToken(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/reload", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if called {
		t.Fatal("handler must not be called without configured authentication")
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
}

func TestLoadServiceTokenRequiresOwnerOnlyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service-token")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 32)), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SERVICE_TOKEN_PATH", path)
	if err := loadServiceToken(); err == nil {
		t.Fatal("group/world-readable token must be rejected")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadServiceToken(); err != nil {
		t.Fatalf("owner-only token rejected: %v", err)
	}
	serviceToken = ""
}

func TestRunAttestation_ConfiguredSigningFailureFailsClosed(t *testing.T) {
	setupTestPolicy()
	policyMu.Lock()
	policy.Attestation.Report.SigningKey = filepath.Join(t.TempDir(), "missing.key")
	policyMu.Unlock()
	report := runAttestation()
	if report.Attestation.Verdict != "fail" || report.Signature != "" {
		t.Fatalf("configured signing failure must produce unsigned fail verdict")
	}
	found := false
	for _, collector := range report.Attestation.Collectors {
		if collector.Name == "report-signing" && collector.Status == "error" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing report-signing failure evidence")
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

func TestMountReadonlyOptionRequiresExactToken(t *testing.T) {
	if !hasMountOption("ro,nosuid,nodev", "ro") {
		t.Fatal("exact ro option was not detected")
	}
	if hasMountOption("rw,errors=remount-ro", "ro") {
		t.Fatal("errors=remount-ro must not be treated as a read-only mount")
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

// ---------------------------------------------------------------------------
// Audit hash chain tests
// ---------------------------------------------------------------------------

func TestAuditHashChain(t *testing.T) {
	dir := t.TempDir()
	auditPath = dir + "/audit.jsonl"
	auditLastHash = ""

	f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	auditFile = f
	auditRequired.Store(true)
	auditHealthy.Store(true)
	defer func() {
		auditFile.Close()
		auditFile = nil
		auditLastHash = ""
		auditRequired.Store(false)
		auditHealthy.Store(false)
	}()

	// Write several audit entries.
	writeAudit(AuditEntry{Action: "attestation", Verdict: "pass", Score: 1.0})
	writeAudit(AuditEntry{Action: "attestation", Verdict: "drift", Score: 0.75})
	writeAudit(AuditEntry{Action: "attestation", Verdict: "pass", Score: 1.0})

	// Read back and verify chain.
	data, _ := os.ReadFile(auditPath)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 audit entries, got %d", len(lines))
	}

	var entries []AuditEntry
	for _, line := range lines {
		var entry AuditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		entries = append(entries, entry)
	}

	// First entry should have empty prev_hash.
	if entries[0].PrevHash != "" {
		t.Fatalf("first entry should have empty prev_hash, got %s", entries[0].PrevHash)
	}

	// All hashes should be non-empty.
	for i, e := range entries {
		if e.Hash == "" {
			t.Fatalf("entry %d has empty hash", i)
		}
	}

	// Subsequent entries should chain.
	for i := 1; i < len(entries); i++ {
		if entries[i].PrevHash != entries[i-1].Hash {
			t.Fatalf("chain broken at entry %d: prev_hash=%s, expected %s",
				i, entries[i].PrevHash, entries[i-1].Hash)
		}
	}

	// Verify hash integrity by recomputing.
	for i, e := range entries {
		expected := computeAuditHash(e)
		if e.Hash != expected {
			t.Fatalf("hash mismatch at entry %d: got %s, expected %s", i, e.Hash, expected)
		}
	}
}

func TestAuditHashChain_TamperDetection(t *testing.T) {
	dir := t.TempDir()
	auditPath = dir + "/audit.jsonl"
	auditLastHash = ""

	f, _ := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	auditFile = f
	auditRequired.Store(true)
	auditHealthy.Store(true)
	defer func() {
		auditFile.Close()
		auditFile = nil
		auditLastHash = ""
		auditRequired.Store(false)
		auditHealthy.Store(false)
	}()

	writeAudit(AuditEntry{Action: "attestation", Verdict: "pass", Score: 1.0})
	writeAudit(AuditEntry{Action: "attestation", Verdict: "drift", Score: 0.75})

	data, _ := os.ReadFile(auditPath)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")

	var entries []AuditEntry
	for _, line := range lines {
		var e AuditEntry
		json.Unmarshal([]byte(line), &e)
		entries = append(entries, e)
	}

	// Tamper with verdict.
	entries[0].Verdict = "TAMPERED"
	recomputed := computeAuditHash(entries[0])
	if recomputed == entries[0].Hash {
		t.Fatal("hash should differ after tampering")
	}
}

func TestRunAttestation_ConfiguredSigningSucceeds(t *testing.T) {
	setupTestPolicy()
	dir := t.TempDir()
	privateKey := filepath.Join(dir, "attestor.key")
	publicKey := filepath.Join(dir, "attestor.pub")
	if err := generateKeypair(privateKey, publicKey); err != nil {
		t.Fatal(err)
	}
	policyMu.Lock()
	policy.Attestation.Report.SigningKey = privateKey
	policyMu.Unlock()
	report := runAttestation()
	if report.Signature == "" || report.SignedAt == "" {
		t.Fatal("configured signing key must produce a signed report")
	}
	if err := verifyReport(report, publicKey); err != nil {
		t.Fatalf("signed attestation did not verify: %v", err)
	}
}

func TestVerifyReport_RejectsTimestampTampering(t *testing.T) {
	dir := t.TempDir()
	privateKey := filepath.Join(dir, "attestor.key")
	publicKey := filepath.Join(dir, "attestor.pub")
	if err := generateKeypair(privateKey, publicKey); err != nil {
		t.Fatal(err)
	}
	report, err := signReport(generateReport(AttestationResult{Verdict: "pass", Score: 1}), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	report.SignedAt = time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	if err := verifyReport(report, publicKey); err == nil {
		t.Fatal("signed_at tampering must invalidate the signature")
	}
}

func TestLoadPolicy_StrictAndRequiresCollectors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	t.Setenv("POLICY_PATH", path)
	if err := os.WriteFile(path, []byte("version: 1\nunknown: true\nattestation: {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadPolicy(); err == nil {
		t.Fatal("unknown policy fields must be rejected")
	}
	if err := os.WriteFile(path, []byte("version: 1\nattestation:\n  collectors: {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := loadPolicy(); err == nil {
		t.Fatal("policy without enabled collectors must be rejected")
	}
}

func TestInitAuditLog_RejectsTamperedChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	entry := AuditEntry{Timestamp: time.Now().UTC().Format(time.RFC3339), Action: "test", Hash: "not-a-valid-hash"}
	data, _ := json.Marshal(entry)
	if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUDIT_LOG_PATH", path)
	auditFile = nil
	auditLastHash = ""
	t.Cleanup(func() {
		auditRequired.Store(false)
		auditHealthy.Store(false)
	})
	if err := initAuditLog(); err == nil {
		t.Fatal("tampered audit chain must prevent startup")
	}
}

func TestVerifyRuntimeAuditRejectsUnknownAndTrailingJSON(t *testing.T) {
	dir := t.TempDir()
	entry := AuditEntry{Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Action: "test"}
	entry.Hash = computeAuditHash(entry)
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	for name, line := range map[string][]byte{
		"unknown":  append(append([]byte{}, data[:len(data)-1]...), []byte(`,"unexpected":true}`)...),
		"trailing": append(append([]byte{}, data...), []byte(` {}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".jsonl")
			if err := os.WriteFile(path, append(line, '\n'), 0600); err != nil {
				t.Fatal(err)
			}
			if err := verifyRuntimeAudit(path); err == nil {
				t.Fatal("non-strict audit JSON must be rejected")
			}
		})
	}
}

func TestRuntimeAuditWriteFailurePoisonsHealth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	auditFile = f
	auditRequired.Store(true)
	auditHealthy.Store(true)
	auditLastHash = ""
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		auditFile = nil
		auditRequired.Store(false)
		auditHealthy.Store(false)
		auditLastHash = ""
	})
	if err := writeAudit(AuditEntry{Action: "test"}); err == nil {
		t.Fatal("closed audit file must fail")
	}
	if auditAvailable() {
		t.Fatal("audit failure must poison service health")
	}
}

func TestPersistTrustReportWritesSignedOwnerOnlyArtifact(t *testing.T) {
	dir := t.TempDir()
	privateKey := filepath.Join(dir, "attestor.key")
	publicKey := filepath.Join(dir, "attestor.pub")
	if err := generateKeypair(privateKey, publicKey); err != nil {
		t.Fatal(err)
	}
	report, err := signReport(generateReport(AttestationResult{Verdict: "pass", Score: 1}), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	outputDir := filepath.Join(dir, "reports")
	if err := persistTrustReport(report, ReportConfig{OutputDir: outputDir, Format: "pretty"}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(outputDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected one persisted report: entries=%d err=%v", len(entries), err)
	}
	path := filepath.Join(outputDir, entries[0].Name())
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("persisted report must be owner-only: mode=%v", info.Mode().Perm())
	}
	persistedData, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var persisted TrustReport
	if err := json.Unmarshal(persistedData, &persisted); err != nil {
		t.Fatal(err)
	}
	if err := verifyReport(persisted, publicKey); err != nil {
		t.Fatalf("persisted report signature is invalid: %v", err)
	}
}

func TestLoadPolicyRejectsGroupWritableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	content := "version: 1\nattestation:\n  collectors:\n    model: true\n"
	if err := os.WriteFile(path, []byte(content), 0620); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0620); err != nil {
		t.Fatal(err)
	}
	t.Setenv("POLICY_PATH", path)
	if err := loadPolicy(); err == nil {
		t.Fatal("group-writable policy must be rejected")
	}
}
