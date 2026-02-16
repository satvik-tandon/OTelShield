package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type createPolicyRequest struct {
	Version  string          `json:"version"`
	Policy   json.RawMessage `json:"policy"`
	Activate *bool           `json:"activate"`
}

type activePolicyResponse struct {
	TenantID  string          `json:"tenantId"`
	Version   string          `json:"version"`
	Policy    json.RawMessage `json:"policy"`
	UpdatedAt string          `json:"updatedAt"`
}

type auditCountRequest struct {
	RuleID string `json:"ruleId"`
	Count  int64  `json:"count"`
	Day    string `json:"day,omitempty"`
}

type auditCountRecord struct {
	RuleID    string `json:"ruleId"`
	Count     int64  `json:"count"`
	UpdatedAt string `json:"updatedAt,omitempty"`
}

type tenantPolicy struct {
	version   string
	policyRaw json.RawMessage
	updatedAt string
}

type auditEntry struct {
	count     int64
	updatedAt string
}

type state struct {
	mu       sync.RWMutex
	policies map[string]tenantPolicy
	// tenant -> day -> ruleID -> aggregate
	audit map[string]map[string]map[string]auditEntry
}

func main() {
	initialPolicy := loadInitialPolicy(os.Getenv("INITIAL_POLICY_PATH"))
	s := &state{
		policies: map[string]tenantPolicy{},
		audit:    map[string]map[string]map[string]auditEntry{},
	}
	if len(initialPolicy) > 0 {
		now := time.Now().UTC().Format(time.RFC3339)
		s.policies["demo"] = tenantPolicy{version: "local-initial", policyRaw: initialPolicy, updatedAt: now}
	}

	addr := os.Getenv("LISTEN_ADDR")
	if strings.TrimSpace(addr) == "" {
		addr = ":8081"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/", s.route)

	log.Printf("mock control plane listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func loadInitialPolicy(path string) json.RawMessage {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Printf("failed to read initial policy file %s: %v", path, err)
		return nil
	}

	var asJSON map[string]any
	if err := json.Unmarshal(raw, &asJSON); err == nil {
		buf, _ := json.Marshal(asJSON)
		return json.RawMessage(buf)
	}

	var asYAML map[string]any
	if err := yaml.Unmarshal(raw, &asYAML); err == nil {
		buf, _ := json.Marshal(asYAML)
		return json.RawMessage(buf)
	}

	log.Printf("initial policy file %s is not valid json/yaml", path)
	return nil
}

func (s *state) route(w http.ResponseWriter, r *http.Request) {
	tenantID, suffix, ok := parseTenantPath(r.URL.Path)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "route not found"})
		return
	}

	switch {
	case r.Method == http.MethodGet && suffix == "/policy/active":
		s.handleGetActive(w, r, tenantID)
	case r.Method == http.MethodPost && suffix == "/policy":
		s.handlePostPolicy(w, r, tenantID)
	case r.Method == http.MethodPost && suffix == "/audit/counts":
		s.handlePostAudit(w, r, tenantID)
	case r.Method == http.MethodGet && suffix == "/audit":
		s.handleGetAudit(w, r, tenantID)
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "route not found"})
	}
}

func parseTenantPath(path string) (tenantID, suffix string, ok bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	// tenants/{tenantId}/...
	if len(parts) < 3 || parts[0] != "tenants" {
		return "", "", false
	}
	tenantID = parts[1]
	suffix = "/" + strings.Join(parts[2:], "/")
	return tenantID, suffix, true
}

func (s *state) handleGetActive(w http.ResponseWriter, r *http.Request, tenantID string) {
	s.mu.RLock()
	policy, found := s.policies[tenantID]
	s.mu.RUnlock()
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "active policy not found"})
		return
	}

	etag := policyETag(policy.version, string(policy.policyRaw))
	if matchesETag(r.Header.Get("If-None-Match"), etag) {
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("ETag", etag)
	writeJSON(w, http.StatusOK, activePolicyResponse{
		TenantID:  tenantID,
		Version:   policy.version,
		Policy:    policy.policyRaw,
		UpdatedAt: policy.updatedAt,
	})
}

func (s *state) handlePostPolicy(w http.ResponseWriter, r *http.Request, tenantID string) {
	defer r.Body.Close()

	var req createPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid json"})
		return
	}
	if len(req.Policy) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "policy is required"})
		return
	}

	version := strings.TrimSpace(req.Version)
	if version == "" {
		version = time.Now().UTC().Format("20060102T150405Z")
	}

	now := time.Now().UTC().Format(time.RFC3339)
	s.mu.Lock()
	s.policies[tenantID] = tenantPolicy{
		version:   version,
		policyRaw: req.Policy,
		updatedAt: now,
	}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"tenantId": tenantID,
		"version":  version,
		"active":   true,
	})
}

func (s *state) handlePostAudit(w http.ResponseWriter, r *http.Request, tenantID string) {
	defer r.Body.Close()

	var req auditCountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid json"})
		return
	}
	req.RuleID = strings.TrimSpace(req.RuleID)
	if req.RuleID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "ruleId is required"})
		return
	}
	if req.Count <= 0 {
		req.Count = 1
	}
	day, err := normalizeDay(req.Day)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	s.mu.Lock()
	if s.audit[tenantID] == nil {
		s.audit[tenantID] = map[string]map[string]auditEntry{}
	}
	if s.audit[tenantID][day] == nil {
		s.audit[tenantID][day] = map[string]auditEntry{}
	}
	entry := s.audit[tenantID][day][req.RuleID]
	entry.count += req.Count
	entry.updatedAt = now
	s.audit[tenantID][day][req.RuleID] = entry
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"tenantId": tenantID,
		"day":      day,
		"ruleId":   req.RuleID,
		"count":    req.Count,
	})
}

func (s *state) handleGetAudit(w http.ResponseWriter, r *http.Request, tenantID string) {
	day, err := normalizeDay(r.URL.Query().Get("day"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	s.mu.RLock()
	dayCounts := s.audit[tenantID][day]
	records := make([]auditCountRecord, 0, len(dayCounts))
	for ruleID, entry := range dayCounts {
		records = append(records, auditCountRecord{
			RuleID:    ruleID,
			Count:     entry.count,
			UpdatedAt: entry.updatedAt,
		})
	}
	s.mu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"tenantId": tenantID,
		"day":      day,
		"counts":   records,
	})
}

func (s *state) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = fmt.Fprintln(w, "# HELP otelshield_audit_rule_total Total redaction hits aggregated by rule.")
	_, _ = fmt.Fprintln(w, "# TYPE otelshield_audit_rule_total gauge")

	s.mu.RLock()
	defer s.mu.RUnlock()

	for tenantID, byDay := range s.audit {
		for day, byRule := range byDay {
			for ruleID, entry := range byRule {
				line := fmt.Sprintf(
					"otelshield_audit_rule_total{tenant_id=%q,day=%q,rule_id=%q} %d",
					escapeMetricLabel(tenantID),
					escapeMetricLabel(day),
					escapeMetricLabel(ruleID),
					entry.count,
				)
				_, _ = fmt.Fprintln(w, line)
			}
		}
	}
}

func escapeMetricLabel(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return v
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func normalizeDay(day string) (string, error) {
	day = strings.TrimSpace(day)
	if day == "" {
		return time.Now().UTC().Format("2006-01-02"), nil
	}
	if _, err := time.Parse("2006-01-02", day); err != nil {
		return "", errors.New("invalid day format, expected YYYY-MM-DD")
	}
	return day, nil
}

func policyETag(version, policyJSON string) string {
	sum := sha256.Sum256([]byte(version + ":" + policyJSON))
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

func matchesETag(ifNoneMatch, etag string) bool {
	if strings.TrimSpace(ifNoneMatch) == "" {
		return false
	}
	for _, candidate := range strings.Split(ifNoneMatch, ",") {
		if strings.TrimSpace(candidate) == etag {
			return true
		}
	}
	return false
}
