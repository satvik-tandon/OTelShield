package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
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

type auditEvent struct {
	RuleID    string `json:"ruleId"`
	Action    string `json:"action"`
	Key       string `json:"key"`
	Signal    string `json:"signal"`
	Count     int64  `json:"count"`
	Timestamp string `json:"timestamp"`
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
	audit    map[string]map[string]map[string]auditEntry
	events   map[string]map[string][]auditEvent

	eventLimit int
}

func main() {
	initialPolicy := loadInitialPolicy(os.Getenv("INITIAL_POLICY_PATH"))
	s := &state{
		policies:   map[string]tenantPolicy{},
		audit:      map[string]map[string]map[string]auditEntry{},
		events:     map[string]map[string][]auditEvent{},
		eventLimit: 5000,
	}
	if len(initialPolicy) > 0 {
		now := time.Now().UTC().Format(time.RFC3339)
		s.policies["demo"] = tenantPolicy{version: "local-initial", policyRaw: initialPolicy, updatedAt: now}
	}

	addr := strings.TrimSpace(os.Getenv("LISTEN_ADDR"))
	if addr == "" {
		addr = ":8081"
	}
	uiDir := strings.TrimSpace(os.Getenv("UI_DIR"))
	if uiDir == "" {
		uiDir = "/ui"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	mux.HandleFunc("/metrics", s.handleMetrics)
	if uiDir != "" {
		mux.Handle("/ui/", http.StripPrefix("/ui/", http.FileServer(http.Dir(uiDir))))
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/ui/", http.StatusFound)
			return
		}
		s.route(w, r)
	})

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
		s.handlePostAuditCount(w, r, tenantID)
	case r.Method == http.MethodGet && suffix == "/audit":
		s.handleGetAudit(w, r, tenantID)
	case r.Method == http.MethodPost && suffix == "/audit/events":
		s.handlePostAuditEvents(w, r, tenantID)
	case r.Method == http.MethodGet && suffix == "/audit/events":
		s.handleGetAuditEvents(w, r, tenantID)
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "route not found"})
	}
}

func parseTenantPath(path string) (tenantID, suffix string, ok bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
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
	activate := true
	if req.Activate != nil {
		activate = *req.Activate
	}

	now := time.Now().UTC().Format(time.RFC3339)
	if activate {
		s.mu.Lock()
		s.policies[tenantID] = tenantPolicy{
			version:   version,
			policyRaw: req.Policy,
			updatedAt: now,
		}
		s.mu.Unlock()
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"tenantId": tenantID,
		"version":  version,
		"active":   activate,
	})
}

func (s *state) handlePostAuditCount(w http.ResponseWriter, r *http.Request, tenantID string) {
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

func (s *state) handlePostAuditEvents(w http.ResponseWriter, r *http.Request, tenantID string) {
	defer r.Body.Close()

	var payload struct {
		Events []auditEvent `json:"events"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid json"})
		return
	}
	events := payload.Events
	if len(events) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "events is required"})
		return
	}

	now := time.Now().UTC()
	accepted := 0
	dropped := 0
	s.mu.Lock()
	if s.events[tenantID] == nil {
		s.events[tenantID] = map[string][]auditEvent{}
	}
	for _, ev := range events {
		ev.RuleID = strings.TrimSpace(ev.RuleID)
		if ev.RuleID == "" {
			dropped++
			continue
		}
		if ev.Count <= 0 {
			ev.Count = 1
		}
		ev.Action = strings.TrimSpace(ev.Action)
		ev.Key = strings.TrimSpace(ev.Key)
		ev.Signal = strings.TrimSpace(ev.Signal)
		ts := parseEventTime(ev.Timestamp, now)
		ev.Timestamp = ts.Format(time.RFC3339Nano)

		day := ts.Format("2006-01-02")
		list := s.events[tenantID][day]
		list = append(list, ev)
		if len(list) > s.eventLimit {
			list = list[len(list)-s.eventLimit:]
		}
		s.events[tenantID][day] = list
		accepted++
	}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"tenantId": tenantID,
		"accepted": accepted,
		"dropped":  dropped,
	})
}

func (s *state) handleGetAuditEvents(w http.ResponseWriter, r *http.Request, tenantID string) {
	day, err := normalizeDay(r.URL.Query().Get("day"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	limit := parseLimit(r.URL.Query().Get("limit"), 200, 2000)
	cursor := strings.TrimSpace(r.URL.Query().Get("cursor"))
	ruleID := strings.TrimSpace(r.URL.Query().Get("ruleId"))
	action := strings.TrimSpace(r.URL.Query().Get("action"))
	signal := strings.TrimSpace(r.URL.Query().Get("signal"))
	key := strings.TrimSpace(r.URL.Query().Get("key"))

	s.mu.RLock()
	list := s.events[tenantID][day]
	s.mu.RUnlock()

	filtered := filterAuditEvents(list, ruleID, action, signal, key)

	endIndex := len(filtered)
	if cursor != "" {
		decoded, err := decodeCursor(cursor)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid cursor"})
			return
		}
		if decoded < 0 || decoded > len(filtered) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "cursor out of range"})
			return
		}
		endIndex = decoded
	}
	startIndex := endIndex - limit
	if startIndex < 0 {
		startIndex = 0
	}

	page := make([]auditEvent, 0, endIndex-startIndex)
	if endIndex > 0 && startIndex < endIndex {
		page = append(page, filtered[startIndex:endIndex]...)
	}

	resp := map[string]any{
		"tenantId": tenantID,
		"day":      day,
		"events":   page,
	}
	if startIndex > 0 {
		resp["nextCursor"] = encodeCursor(startIndex)
	}
	writeJSON(w, http.StatusOK, resp)
}

func filterAuditEvents(events []auditEvent, ruleID, action, signal, key string) []auditEvent {
	if ruleID == "" && action == "" && signal == "" && key == "" {
		return events
	}
	ruleIDLower := strings.ToLower(ruleID)
	keyLower := strings.ToLower(key)
	out := make([]auditEvent, 0, len(events))
	for _, ev := range events {
		if ruleID != "" && !strings.Contains(strings.ToLower(strings.TrimSpace(ev.RuleID)), ruleIDLower) {
			continue
		}
		if action != "" && !strings.EqualFold(strings.TrimSpace(ev.Action), action) {
			continue
		}
		if signal != "" && !strings.EqualFold(strings.TrimSpace(ev.Signal), signal) {
			continue
		}
		if key != "" && !strings.Contains(strings.ToLower(strings.TrimSpace(ev.Key)), keyLower) {
			continue
		}
		out = append(out, ev)
	}
	return out
}

func parseEventTime(raw string, fallback time.Time) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback.UTC()
	}
	if ts, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return ts.UTC()
	}
	if ts, err := time.Parse(time.RFC3339, raw); err == nil {
		return ts.UTC()
	}
	return fallback.UTC()
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
	v = strings.ReplaceAll(v, `\\`, `\\\\`)
	v = strings.ReplaceAll(v, `"`, `\\"`)
	v = strings.ReplaceAll(v, "\n", `\\n`)
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

func parseLimit(raw string, fallback, max int) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit <= 0 {
		return fallback
	}
	if limit > max {
		return max
	}
	return limit
}

func encodeCursor(index int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(index)))
}

func decodeCursor(cursor string) (int, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(cursor))
	if err != nil {
		return 0, err
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(decoded)))
	if err != nil {
		return 0, err
	}
	return value, nil
}
