package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Policy types
// ---------------------------------------------------------------------------

type AttestationPolicy struct {
	Version     int          `yaml:"version"`
	Attestation AttestConfig `yaml:"attestation"`
}

type AttestConfig struct {
	Collectors CollectorToggle   `yaml:"collectors"`
	Model      ModelConfig       `yaml:"model"`
	Container  ContainerConfig   `yaml:"container"`
	Network    NetworkConfig     `yaml:"network"`
	Mount      MountConfig       `yaml:"mount"`
	GPU        GPUConfig         `yaml:"gpu"`
	Policy     PolicyFilesConfig `yaml:"policy"`
	Report     ReportConfig      `yaml:"report"`
	Daemon     DaemonConfig      `yaml:"daemon"`
	RateLimit  RateLimitConfig   `yaml:"rate_limit"`
	Privacy    PrivacyProfile    `yaml:"privacy"`
}

type CollectorToggle struct {
	Model     bool `yaml:"model"`
	Container bool `yaml:"container"`
	Network   bool `yaml:"network"`
	Mount     bool `yaml:"mount"`
	GPU       bool `yaml:"gpu"`
	Policy    bool `yaml:"policy"`
}

type ModelConfig struct {
	VaultDir         string   `yaml:"vault_dir"`
	RegistryURL      string   `yaml:"registry_url"`
	RegistryTokenEnv string   `yaml:"registry_token_env"`
	AllowedFormats   []string `yaml:"allowed_formats"`
	MaxFileSize      int64    `yaml:"max_file_size"`
}

type ContainerConfig struct {
	Runtime        string   `yaml:"runtime"`
	ExpectedImages []string `yaml:"expected_images"`
}

type NetworkConfig struct {
	AllowedListeners        []string `yaml:"allowed_listeners"`
	DenyUnexpectedListeners bool     `yaml:"deny_unexpected_listeners"`
}

type MountConfig struct {
	Expected []MountExpectation `yaml:"expected"`
}

type MountExpectation struct {
	Path     string `yaml:"path"`
	FSType   string `yaml:"fstype"`
	ReadOnly bool   `yaml:"readonly"`
}

type GPUConfig struct {
	AllowedDevices        []string `yaml:"allowed_devices"`
	DenyUnexpectedDevices bool     `yaml:"deny_unexpected_devices"`
}

type PolicyFilesConfig struct {
	Files          map[string]string `yaml:"files"`
	ApprovedHashes map[string]string `yaml:"approved_hashes"`
}

type ReportConfig struct {
	SigningKey string `yaml:"signing_key"`
	OutputDir  string `yaml:"output_dir"`
	Format     string `yaml:"format"`
}

type DaemonConfig struct {
	IntervalSeconds int    `yaml:"interval_seconds"`
	BindAddr        string `yaml:"bind_addr"`
	ReadTimeoutSec  int    `yaml:"read_timeout_seconds"`
	WriteTimeoutSec int    `yaml:"write_timeout_seconds"`
	IdleTimeoutSec  int    `yaml:"idle_timeout_seconds"`
}

type RateLimitConfig struct {
	RequestsPerMinute int `yaml:"requests_per_minute"`
}

// PrivacyProfile controls what gets stripped from audit logs and reports.
type PrivacyProfile struct {
	StripHostname    bool `yaml:"strip_hostname"`
	StripPaths       bool `yaml:"strip_paths"`
	StripListeners   bool `yaml:"strip_listeners"`
	StripPolicyNames bool `yaml:"strip_policy_names"`
}

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

var (
	policyMu sync.RWMutex
	policy   AttestationPolicy

	latestReportMu sync.RWMutex
	latestReport   *TrustReport
	attestationMu  sync.Mutex

	auditFile      *os.File
	auditMu        sync.Mutex
	auditPath      string
	auditLastHash  string
	auditRequired  atomic.Bool
	auditHealthy   atomic.Bool
	persistReports atomic.Bool

	rateMu      sync.Mutex
	rateCounter int64
	rateWindow  time.Time

	totalRequests  atomic.Int64
	attestRequests atomic.Int64

	serviceToken string
)

const (
	defaultPolicyPath = "/etc/secure-ai/policy/attestor.yaml"
	// #nosec G101 -- this is a filesystem location for a runtime-mounted token, not credential material.
	defaultTokenPath   = "/run/secure-ai/service-token"
	defaultAuditPath   = "/var/lib/secure-ai/logs/attestor-audit.jsonl"
	defaultBindAddr    = "127.0.0.1:8485"
	defaultRPM         = 60
	maxRequestBodySize = 1 << 20 // 1 MiB
	maxPolicySize      = 1 << 20
	maxReportSize      = 8 << 20
	maxAuditSize       = 64 << 20
	maxAuditLine       = 64 << 10
)

// ---------------------------------------------------------------------------
// Policy loading
// ---------------------------------------------------------------------------

func policyFilePath() string {
	if p := os.Getenv("POLICY_PATH"); p != "" {
		return p
	}
	return defaultPolicyPath
}

func loadPolicy() error {
	p, err := parsePolicyFile(policyFilePath())
	if err != nil {
		return err
	}
	policyMu.Lock()
	policy = p
	policyMu.Unlock()
	log.Printf("policy loaded from %s (version=%d)", policyFilePath(), p.Version)
	return nil
}

func parsePolicyFile(path string) (AttestationPolicy, error) {
	data, err := readTrustedConfigFile(path, maxPolicySize)
	if err != nil {
		return AttestationPolicy{}, fmt.Errorf("read policy: %w", err)
	}
	var p AttestationPolicy
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&p); err != nil {
		return AttestationPolicy{}, fmt.Errorf("parse policy: %w", err)
	}
	if err := ensureYAMLEOF(decoder); err != nil {
		return AttestationPolicy{}, fmt.Errorf("parse policy: %w", err)
	}
	if err := validatePolicy(p); err != nil {
		return AttestationPolicy{}, fmt.Errorf("validate policy: %w", err)
	}
	return p, nil
}

func ensureYAMLEOF(decoder *yaml.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple YAML documents are not allowed")
		}
		return err
	}
	return nil
}

func validatePolicy(p AttestationPolicy) error {
	if p.Version != 1 {
		return fmt.Errorf("unsupported policy version %d", p.Version)
	}
	c := p.Attestation.Collectors
	if !c.Model && !c.Container && !c.Network && !c.Mount && !c.GPU && !c.Policy {
		return fmt.Errorf("at least one collector must be enabled")
	}
	if p.Attestation.Daemon.IntervalSeconds < 0 ||
		p.Attestation.RateLimit.RequestsPerMinute < 0 {
		return fmt.Errorf("interval and rate limits cannot be negative")
	}
	if runtimeName := p.Attestation.Container.Runtime; runtimeName != "" && runtimeName != "podman" && runtimeName != "docker" {
		return fmt.Errorf("container runtime must be podman or docker")
	}
	for _, mount := range p.Attestation.Mount.Expected {
		if !filepath.IsAbs(mount.Path) || filepath.Clean(mount.Path) != mount.Path {
			return fmt.Errorf("mount paths must be canonical and absolute")
		}
	}
	for _, path := range p.Attestation.Policy.Files {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("policy evidence paths must be canonical and absolute")
		}
	}
	if outputDir := p.Attestation.Report.OutputDir; outputDir != "" &&
		(!filepath.IsAbs(outputDir) || filepath.Clean(outputDir) != outputDir) {
		return fmt.Errorf("report output directory must be canonical and absolute")
	}
	if format := p.Attestation.Report.Format; format != "" && format != "json" && format != "pretty" {
		return fmt.Errorf("report format must be json or pretty")
	}
	return nil
}

func readBoundedRegularFile(path string, limit int64) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("path is empty")
	}
	resolved, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	before, err := os.Lstat(resolved)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 ||
		before.Size() < 0 || before.Size() > limit {
		return nil, fmt.Errorf("path is not a bounded regular file")
	}
	// #nosec G304 -- resolved was Lstat-validated as a bounded regular non-symlink and is identity-checked after open.
	f, err := os.Open(resolved)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	afterOpen, err := f.Stat()
	if err != nil || !os.SameFile(before, afterOpen) {
		return nil, fmt.Errorf("file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds %d-byte limit", limit)
	}
	afterRead, err := f.Stat()
	if err != nil || !os.SameFile(afterOpen, afterRead) || afterRead.Size() != int64(len(data)) {
		return nil, fmt.Errorf("file changed while reading")
	}
	return data, nil
}

func readTrustedConfigFile(path string, limit int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm()&0o022 != 0 || !trustedFileOwner(before) {
		return nil, fmt.Errorf("policy must be a non-writable regular file owned by root or the service user")
	}
	data, err := readBoundedRegularFile(path, limit)
	if err != nil {
		return nil, err
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || after.Mode().Perm()&0o022 != 0 || !trustedFileOwner(after) {
		return nil, fmt.Errorf("policy changed while validating trust")
	}
	return data, nil
}

func trustedFileOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return true
	}
	euid := int64(os.Geteuid())
	return stat.Uid == 0 || (euid >= 0 && int64(stat.Uid) == euid)
}

func readOwnerOnlyFile(path string, limit int64) ([]byte, error) {
	// #nosec G703 -- callers provide a local key/token path whose type, owner, mode, bounds, and identity are checked before and after the read.
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm()&0o077 != 0 || !trustedFileOwner(before) {
		return nil, fmt.Errorf("file must be regular and owner-only")
	}
	data, err := readBoundedRegularFile(path, limit)
	if err != nil {
		return nil, err
	}
	// #nosec G703 -- post-read identity, ownership, and permission validation closes the trust check.
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || after.Mode().Perm()&0o077 != 0 || !trustedFileOwner(after) {
		return nil, fmt.Errorf("file changed while validating permissions")
	}
	return data, nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".runtime-attestor-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}
	if err := tmp.Chmod(mode); err != nil {
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	// #nosec G304 -- dir is the parent of the caller-authorized atomic output and this handle is used only for fsync.
	dirHandle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer dirHandle.Close()
	return dirHandle.Sync()
}

func getPolicy() AttestationPolicy {
	policyMu.RLock()
	p := policy
	policyMu.RUnlock()
	return p
}

// ---------------------------------------------------------------------------
// Audit logging (structured JSONL)
// ---------------------------------------------------------------------------

type AuditEntry struct {
	Timestamp string  `json:"timestamp"`
	Action    string  `json:"action"`
	Verdict   string  `json:"verdict,omitempty"`
	Score     float64 `json:"score,omitempty"`
	Source    string  `json:"source,omitempty"`
	Error     string  `json:"error,omitempty"`
	Hash      string  `json:"hash"`
	PrevHash  string  `json:"prev_hash,omitempty"`
}

func initAuditLog() error {
	auditRequired.Store(true)
	auditHealthy.Store(false)
	auditLastHash = ""
	auditPath = os.Getenv("AUDIT_LOG_PATH")
	if auditPath == "" {
		auditPath = defaultAuditPath
	}
	if !filepath.IsAbs(auditPath) || filepath.Clean(auditPath) != auditPath {
		return fmt.Errorf("audit path must be canonical and absolute")
	}
	dir := filepath.Dir(auditPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create audit directory: %w", err)
	}
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o022 != 0 || !trustedFileOwner(info) {
		return fmt.Errorf("audit directory is unsafe")
	}
	if err := verifyRuntimeAudit(auditPath); err != nil {
		return err
	}

	f, err := openSafeAppend(auditPath)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	auditFile = f
	auditHealthy.Store(true)
	return nil
}

func verifyRuntimeAudit(path string) error {
	// #nosec G304 -- initAuditLog requires a canonical absolute path and safe parent; this function rechecks identity, owner, mode, and bounds.
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read audit log: %w", err)
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Size() > maxAuditSize ||
		opened.Mode().Perm()&0o077 != 0 || !trustedFileOwner(opened) {
		return fmt.Errorf("audit log is unsafe, oversized, or has weak permissions")
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, pathInfo) {
		return fmt.Errorf("audit path is unsafe or changed while opening")
	}
	expectedPrev := ""
	scanner := bufio.NewScanner(io.LimitReader(f, maxAuditSize+1))
	scanner.Buffer(make([]byte, 4096), maxAuditLine)
	line := 0
	for scanner.Scan() {
		line++
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.DisallowUnknownFields()
		var entry AuditEntry
		if err := decoder.Decode(&entry); err != nil {
			return fmt.Errorf("decode audit line %d: %w", line, err)
		}
		if err := ensureJSONEOF(decoder); err != nil {
			return fmt.Errorf("decode audit line %d: %w", line, err)
		}
		if entry.Action == "" || entry.PrevHash != expectedPrev || entry.Hash != computeAuditHash(entry) {
			return fmt.Errorf("audit integrity failure at line %d", line)
		}
		if _, err := time.Parse(time.RFC3339Nano, entry.Timestamp); err != nil {
			return fmt.Errorf("invalid audit timestamp at line %d", line)
		}
		expectedPrev = entry.Hash
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan audit log: %w", err)
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(opened, after) || after.Size() != opened.Size() {
		return fmt.Errorf("audit log changed while reading")
	}
	auditLastHash = expectedPrev
	return nil
}

func openSafeAppend(path string) (*os.File, error) {
	// #nosec G304 -- the canonical audit path and parent are validated by initAuditLog and the opened inode is revalidated below.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	opened, statErr := f.Stat()
	pathInfo, lstatErr := os.Lstat(path)
	if statErr != nil || lstatErr != nil || !opened.Mode().IsRegular() ||
		pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, pathInfo) ||
		opened.Mode().Perm()&0o077 != 0 || !trustedFileOwner(opened) || opened.Size() > maxAuditSize {
		f.Close()
		return nil, fmt.Errorf("audit path is unsafe or changed while opening")
	}
	return f, nil
}

// computeAuditHash returns a SHA-256 digest over all fields except Hash.
func computeAuditHash(entry AuditEntry) string {
	canonical := struct {
		Timestamp string  `json:"timestamp"`
		Action    string  `json:"action"`
		Verdict   string  `json:"verdict,omitempty"`
		Score     float64 `json:"score,omitempty"`
		Source    string  `json:"source,omitempty"`
		Error     string  `json:"error,omitempty"`
		PrevHash  string  `json:"prev_hash,omitempty"`
	}{
		Timestamp: entry.Timestamp,
		Action:    entry.Action,
		Verdict:   entry.Verdict,
		Score:     entry.Score,
		Source:    entry.Source,
		Error:     entry.Error,
		PrevHash:  entry.PrevHash,
	}
	data, _ := json.Marshal(canonical)
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func auditAvailable() bool {
	return !auditRequired.Load() || auditHealthy.Load()
}

func writeAudit(entry AuditEntry) error {
	if auditFile == nil {
		if auditRequired.Load() {
			return fmt.Errorf("audit log is unavailable")
		}
		return nil
	}
	auditMu.Lock()
	defer auditMu.Unlock()
	if !auditHealthy.Load() {
		return fmt.Errorf("audit log is unhealthy")
	}
	entry.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	entry.PrevHash = auditLastHash
	entry.Hash = computeAuditHash(entry)

	data, err := json.Marshal(entry)
	if err != nil {
		auditHealthy.Store(false)
		return fmt.Errorf("audit marshal: %w", err)
	}
	line := append(data, '\n')
	info, err := auditFile.Stat()
	pathInfo, pathErr := os.Lstat(auditPath)
	if err != nil || pathErr != nil || !os.SameFile(info, pathInfo) || pathInfo.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 || !trustedFileOwner(info) {
		auditHealthy.Store(false)
		return fmt.Errorf("audit path changed or became unsafe")
	}
	if info.Size() > maxAuditSize-int64(len(line)) {
		auditHealthy.Store(false)
		return fmt.Errorf("audit log reached its %d-byte rotation limit", maxAuditSize)
	}
	written, err := auditFile.Write(line)
	if err != nil || written != len(line) {
		if err == nil {
			err = io.ErrShortWrite
		}
		auditHealthy.Store(false)
		return fmt.Errorf("audit write: %w", err)
	}
	if err := auditFile.Sync(); err != nil {
		auditHealthy.Store(false)
		return fmt.Errorf("audit sync: %w", err)
	}
	auditLastHash = entry.Hash
	return nil
}

// ---------------------------------------------------------------------------
// Service token authentication
// ---------------------------------------------------------------------------

func loadServiceToken() error {
	tokenPath := os.Getenv("SERVICE_TOKEN_PATH")
	if tokenPath == "" {
		tokenPath = defaultTokenPath
	}
	data, err := readOwnerOnlyFile(tokenPath, 4096)
	if err != nil {
		return fmt.Errorf("read service token: %w", err)
	}
	serviceToken = strings.TrimSpace(string(data))
	if len(serviceToken) < 32 {
		return fmt.Errorf("service token must contain at least 32 characters")
	}
	log.Printf("service token loaded")
	return nil
}

func requireServiceToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if serviceToken == "" {
			http.Error(w, "service authentication unavailable", http.StatusServiceUnavailable)
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "forbidden: invalid service token"})
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(serviceToken)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "forbidden: invalid service token"})
			return
		}
		if !auditAvailable() {
			http.Error(w, "audit subsystem unavailable", http.StatusServiceUnavailable)
			return
		}
		if !checkRateLimit() {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

func checkRateLimit() bool {
	pol := getPolicy()
	rpm := pol.Attestation.RateLimit.RequestsPerMinute
	if rpm <= 0 {
		rpm = defaultRPM
	}
	rateMu.Lock()
	defer rateMu.Unlock()
	now := time.Now()
	if now.Sub(rateWindow) > time.Minute {
		rateCounter = 0
		rateWindow = now
	}
	rateCounter++
	return rateCounter <= int64(rpm)
}

// ---------------------------------------------------------------------------
// Core attestation logic
// ---------------------------------------------------------------------------

// runAttestation executes all enabled collectors and returns a trust report.
func runAttestation() TrustReport {
	attestationMu.Lock()
	defer attestationMu.Unlock()
	pol := getPolicy()
	cfg := pol.Attestation
	var results []CollectorResult

	if cfg.Collectors.Model {
		results = append(results, collectModelState(cfg.Model))
	}
	if cfg.Collectors.Container {
		results = append(results, collectContainerState(cfg.Container))
	}
	if cfg.Collectors.Network {
		results = append(results, collectNetworkState(cfg.Network))
	}
	if cfg.Collectors.Mount {
		results = append(results, collectMountState(cfg.Mount))
	}
	if cfg.Collectors.GPU {
		results = append(results, collectGPUState(cfg.GPU))
	}
	if cfg.Collectors.Policy {
		results = append(results, collectPolicyState(cfg.Policy))
	}

	att := compare(results)
	report := generateReport(att)

	// Apply privacy redaction if configured.
	if cfg.Privacy != (PrivacyProfile{}) {
		report = redactReport(report, cfg.Privacy)
	}

	// A trust report without an operator-controlled signature is observation,
	// not portable attestation, so signing is mandatory for a passing verdict.
	if cfg.Report.SigningKey != "" {
		signed, err := signReport(report, cfg.Report.SigningKey)
		if err != nil {
			log.Printf("attestation signing failed: %v", err)
			report.Attestation.Verdict = "fail"
			report.Attestation.Score = 0
			report.Attestation.Collectors = append(report.Attestation.Collectors, CollectorResult{
				Name:      "report-signing",
				Status:    "error",
				Error:     "configured signing failed",
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			})
		} else {
			report = signed
		}
	} else {
		report.Attestation.Verdict = "fail"
		report.Attestation.Score = 0
		report.Attestation.Collectors = append(report.Attestation.Collectors, CollectorResult{
			Name: "report-signing", Status: "error", Error: "signing key is not configured",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
	}

	auditErr := writeAudit(AuditEntry{
		Action:  "attestation",
		Verdict: report.Attestation.Verdict,
		Score:   report.Attestation.Score,
	})
	if auditErr != nil && auditRequired.Load() {
		log.Printf("attestation audit failed: %v", auditErr)
		report = markReportFailure(report, cfg, "audit-persistence", "audit persistence failed")
	} else if persistReports.Load() && cfg.Report.OutputDir != "" && report.Signature != "" {
		if err := persistTrustReport(report, cfg.Report); err != nil {
			log.Printf("report persistence failed: %v", err)
			report = markReportFailure(report, cfg, "report-persistence", "configured report persistence failed")
			if err := writeAudit(AuditEntry{Action: "report_persistence", Verdict: "fail", Score: 0, Error: "report persistence failed"}); err != nil {
				log.Printf("report persistence audit failed: %v", err)
			}
		}
	}

	// Store only the final, possibly fail-closed report as latest.
	latestReportMu.Lock()
	latestReport = &report
	latestReportMu.Unlock()

	log.Printf("attestation complete: verdict=%s score=%.2f collectors=%d",
		report.Attestation.Verdict, report.Attestation.Score, len(results))

	return report
}

func markReportFailure(report TrustReport, cfg AttestConfig, collector, message string) TrustReport {
	report.Signature = ""
	report.PublicKey = ""
	report.SignedAt = ""
	report.Attestation.Verdict = "fail"
	report.Attestation.Score = 0
	report.Attestation.Collectors = append(report.Attestation.Collectors, CollectorResult{
		Name: collector, Status: "error", Error: message,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	if cfg.Report.SigningKey != "" {
		if signed, err := signReport(report, cfg.Report.SigningKey); err == nil {
			return signed
		}
	}
	return report
}

func persistTrustReport(report TrustReport, cfg ReportConfig) error {
	if report.Signature == "" {
		return fmt.Errorf("refusing to persist an unsigned report")
	}
	if !filepath.IsAbs(cfg.OutputDir) || filepath.Clean(cfg.OutputDir) != cfg.OutputDir {
		return fmt.Errorf("report output directory must be canonical and absolute")
	}
	if err := os.MkdirAll(cfg.OutputDir, 0o700); err != nil {
		return fmt.Errorf("create report directory: %w", err)
	}
	info, err := os.Lstat(cfg.OutputDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o022 != 0 || !trustedFileOwner(info) {
		return fmt.Errorf("report output directory is unsafe")
	}
	var data []byte
	if cfg.Format == "pretty" {
		data, err = json.MarshalIndent(report, "", "  ")
	} else {
		data, err = json.Marshal(report)
	}
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	digest := sha256.Sum256(data)
	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	path := filepath.Join(cfg.OutputDir, fmt.Sprintf("trust-report-%s-%s.json", stamp, hex.EncodeToString(digest[:6])))
	if err := writeFileAtomic(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// HTTP handlers (daemon mode)
// ---------------------------------------------------------------------------

func handleHealth(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	status := "ok"
	statusCode := http.StatusOK
	if !auditAvailable() {
		status = "unhealthy"
		statusCode = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  status,
		"service": "runtime-attestor",
	})
}

func handleAttest(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)
	attestRequests.Add(1)

	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	report := runAttestation()
	if !auditAvailable() {
		http.Error(w, "audit persistence failed", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}

func handleLatestReport(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	latestReportMu.RLock()
	rpt := latestReport
	latestReportMu.RUnlock()

	if rpt == nil {
		http.Error(w, "no attestation report available yet", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rpt)
}

func handleReload(w http.ResponseWriter, r *http.Request) {
	totalRequests.Add(1)

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	newPolicy, err := parsePolicyFile(policyFilePath())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	if getPolicy().Attestation.Daemon != newPolicy.Attestation.Daemon {
		http.Error(w, "daemon changes require a restart", http.StatusConflict)
		return
	}
	if err := writeAudit(AuditEntry{Action: "policy_reload", Source: r.RemoteAddr}); err != nil {
		http.Error(w, "audit persistence failed", http.StatusInternalServerError)
		return
	}
	policyMu.Lock()
	policy = newPolicy
	policyMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "policy reloaded"})
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int64{
		"total_requests":  totalRequests.Load(),
		"attest_requests": attestRequests.Load(),
	})
}

// ---------------------------------------------------------------------------
// Daemon mode
// ---------------------------------------------------------------------------

func runDaemon(bindAddr string, interval time.Duration) {
	if err := loadServiceToken(); err != nil {
		log.Fatalf("service authentication unavailable: %v", err)
	}
	if err := initAuditLog(); err != nil {
		log.Fatalf("audit integrity unavailable: %v", err)
	}
	defer auditFile.Close()
	persistReports.Store(true)
	defer persistReports.Store(false)

	mux := buildMux()

	// Run initial attestation.
	runAttestation()

	// Periodic attestation.
	if interval > 0 {
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for range ticker.C {
				if auditAvailable() {
					runAttestation()
				}
			}
		}()
		log.Printf("periodic attestation every %s", interval)
	}

	pol := getPolicy()
	readTimeout := pol.Attestation.Daemon.ReadTimeoutSec
	if readTimeout <= 0 {
		readTimeout = 30
	}
	writeTimeout := pol.Attestation.Daemon.WriteTimeoutSec
	if writeTimeout <= 0 {
		writeTimeout = 60
	}
	idleTimeout := pol.Attestation.Daemon.IdleTimeoutSec
	if idleTimeout <= 0 {
		idleTimeout = 120
	}

	srv := &http.Server{
		Addr:              bindAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       time.Duration(readTimeout) * time.Second,
		WriteTimeout:      time.Duration(writeTimeout) * time.Second,
		IdleTimeout:       time.Duration(idleTimeout) * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	log.Printf("runtime-attestor daemon listening on %s", bindAddr)
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- srv.ListenAndServe() }()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	select {
	case err := <-serverErrors:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	case <-signals:
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("server shutdown failed: %v", err)
		}
	}
}

// buildMux constructs the HTTP handler. Auth required on all non-health endpoints.
func buildMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/v1/attest", requireServiceToken(handleAttest))
	mux.HandleFunc("/v1/report/latest", requireServiceToken(handleLatestReport))
	mux.HandleFunc("/v1/reload", requireServiceToken(handleReload))
	mux.HandleFunc("/v1/metrics", requireServiceToken(handleMetrics))
	return mux
}

// ---------------------------------------------------------------------------
// CLI commands
// ---------------------------------------------------------------------------

func cmdAttest(policyPath, outputPath, format, keyPath string) int {
	os.Setenv("POLICY_PATH", policyPath)
	if err := loadPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	// Override signing key if provided via flag.
	if keyPath != "" {
		policyMu.Lock()
		policy.Attestation.Report.SigningKey = keyPath
		policyMu.Unlock()
	}

	report := runAttestation()

	var data []byte
	var err error
	if format == "pretty" {
		data, err = json.MarshalIndent(report, "", "  ")
	} else {
		data, err = json.Marshal(report)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error marshalling report: %v\n", err)
		return 1
	}

	if outputPath != "" && outputPath != "-" {
		if err := writeFileAtomic(outputPath, append(data, '\n'), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "error writing output: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "report written to %s\n", outputPath)
	} else {
		fmt.Println(string(data))
	}

	// Exit code reflects verdict.
	switch report.Attestation.Verdict {
	case "pass":
		return 0
	case "drift":
		return 2
	default:
		return 3
	}
}

func cmdVerify(reportPath, pubKeyPath string) int {
	data, err := readBoundedRegularFile(reportPath, maxReportSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading report: %v\n", err)
		return 1
	}

	var report TrustReport
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing report: %v\n", err)
		return 1
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		fmt.Fprintln(os.Stderr, "error parsing report: trailing JSON data")
		return 1
	}

	if report.Signature == "" {
		fmt.Fprintf(os.Stderr, "report is unsigned\n")
		return 1
	}

	if err := verifyReport(report, pubKeyPath); err != nil {
		fmt.Fprintf(os.Stderr, "VERIFICATION FAILED: %v\n", err)
		return 1
	}

	fmt.Printf("signature valid\n")
	fmt.Printf("  verdict:  %s\n", report.Attestation.Verdict)
	fmt.Printf("  score:    %.2f\n", report.Attestation.Score)
	fmt.Printf("  hostname: %s\n", report.Hostname)
	fmt.Printf("  signed:   %s\n", report.SignedAt)
	return 0
}

func cmdKeygen(privPath, pubPath string) int {
	if err := generateKeypair(privPath, pubPath); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	fmt.Printf("keypair generated:\n  private: %s\n  public:  %s\n", privPath, pubPath)
	return 0
}

func cmdDaemon(policyPath, bindAddr string, intervalSec int) int {
	os.Setenv("POLICY_PATH", policyPath)
	if err := loadPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	if bindAddr == "" {
		bindAddr = getPolicy().Attestation.Daemon.BindAddr
		if bindAddr == "" {
			bindAddr = defaultBindAddr
		}
	}

	interval := time.Duration(intervalSec) * time.Second
	if intervalSec <= 0 {
		sec := getPolicy().Attestation.Daemon.IntervalSeconds
		if sec <= 0 {
			sec = 300
		}
		interval = time.Duration(sec) * time.Second
	}

	runDaemon(bindAddr, interval)
	return 0
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "attest":
		fs := flag.NewFlagSet("attest", flag.ExitOnError)
		policyPath := fs.String("policy", defaultPolicyPath, "path to policy file")
		output := fs.String("output", "-", "output file (- for stdout)")
		format := fs.String("format", "pretty", "output format: json, pretty")
		key := fs.String("key", "", "signing key path (overrides policy)")
		fs.Parse(os.Args[2:])
		os.Exit(cmdAttest(*policyPath, *output, *format, *key))

	case "verify":
		fs := flag.NewFlagSet("verify", flag.ExitOnError)
		reportPath := fs.String("report", "", "path to trust report file")
		pubKey := fs.String("pubkey", "", "path to public key file")
		fs.Parse(os.Args[2:])
		if *reportPath == "" {
			fmt.Fprintf(os.Stderr, "error: -report is required\n")
			os.Exit(1)
		}
		os.Exit(cmdVerify(*reportPath, *pubKey))

	case "daemon":
		fs := flag.NewFlagSet("daemon", flag.ExitOnError)
		policyPath := fs.String("policy", defaultPolicyPath, "path to policy file")
		bind := fs.String("bind", "", "bind address (overrides policy)")
		interval := fs.Int("interval", 0, "attestation interval seconds (overrides policy)")
		fs.Parse(os.Args[2:])
		os.Exit(cmdDaemon(*policyPath, *bind, *interval))

	case "keygen":
		fs := flag.NewFlagSet("keygen", flag.ExitOnError)
		privPath := fs.String("priv", "attestor.key", "private key output path")
		pubPath := fs.String("pub", "attestor.pub", "public key output path")
		fs.Parse(os.Args[2:])
		os.Exit(cmdKeygen(*privPath, *pubPath))

	case "audit-checkpoint":
		fs := flag.NewFlagSet("audit-checkpoint", flag.ExitOnError)
		source := fs.String("audit", defaultAuditPath, "canonical absolute offline audit log path")
		key := fs.String("key", "", "canonical absolute owner-only Ed25519 private key path")
		output := fs.String("output", "", "canonical absolute new checkpoint output path")
		fs.Parse(os.Args[2:])
		if *key == "" || *output == "" {
			fmt.Fprintln(os.Stderr, "error: -key and -output are required")
			os.Exit(1)
		}
		os.Exit(cmdAuditCheckpoint(*source, *key, *output))

	case "audit-verify":
		fs := flag.NewFlagSet("audit-verify", flag.ExitOnError)
		checkpoint := fs.String("checkpoint", "", "checkpoint file path")
		pubKey := fs.String("pubkey", "", "canonical absolute trusted Ed25519 public key path")
		requiredHead := fs.String("require-head", "", "independently retained chain head required in the checkpoint")
		fs.Parse(os.Args[2:])
		if *checkpoint == "" || *pubKey == "" {
			fmt.Fprintln(os.Stderr, "error: -checkpoint and -pubkey are required")
			os.Exit(1)
		}
		os.Exit(cmdAuditVerify(*checkpoint, *pubKey, *requiredHead))

	case "audit-recover":
		fs := flag.NewFlagSet("audit-recover", flag.ExitOnError)
		checkpoint := fs.String("checkpoint", "", "checkpoint file path")
		pubKey := fs.String("pubkey", "", "canonical absolute trusted Ed25519 public key path")
		output := fs.String("output", "", "canonical absolute new audit log output path (must not exist)")
		requiredHead := fs.String("require-head", "", "independently retained chain head required in the checkpoint")
		fs.Parse(os.Args[2:])
		if *checkpoint == "" || *pubKey == "" || *output == "" || *requiredHead == "" {
			fmt.Fprintln(os.Stderr, "error: -checkpoint, -pubkey, -output, and -require-head are required")
			os.Exit(1)
		}
		os.Exit(cmdAuditRecover(*checkpoint, *pubKey, *output, *requiredHead))

	case "-h", "--help", "help":
		printUsage()
		os.Exit(0)

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `runtime-attestor — runtime trust verification for SecAI_OS

Usage:
  runtime-attestor <command> [options]

Commands:
  attest    Run attestation and emit a signed trust report
  verify    Verify the signature on a trust report
  daemon    Run as HTTP daemon with periodic attestation
  keygen    Generate ed25519 signing keypair
  audit-checkpoint  Export a signed, no-overwrite local audit checkpoint
  audit-verify      Verify checkpoint signature, bytes, chain, and optional anchor
  audit-recover     Recover verified bytes to a new path using a retained anchor

Exit codes (attest):
  0  All checks passed
  2  Drift detected
  3  Hard failure detected

Use "runtime-attestor <command> -h" for command-specific options.
`)
}
