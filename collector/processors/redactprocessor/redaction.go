package redactprocessor

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

type maskRule struct {
	ruleID      string
	re          *regexp.Regexp
	replacement string
}

type tokenizeRule struct {
	keyID  string
	ruleID string
}

type compiledPolicy struct {
	dropKeys           map[string]string
	tokenizeKeys       map[string]tokenizeRule
	hmacSecrets        map[string][]byte
	maskAttributeRules map[string][]maskRule
	maskResourceRules  map[string][]maskRule
	maskLogBodyRules   []maskRule
}

type policyFile struct {
	Rules       []Rule            `yaml:"rules" json:"rules"`
	HMACSecrets map[string]string `yaml:"hmac_secrets" json:"hmac_secrets"`
}

type auditEvent struct {
	RuleID    string `json:"ruleId"`
	Action    string `json:"action"`
	Key       string `json:"key"`
	Signal    string `json:"signal"`
	Count     int64  `json:"count"`
	Timestamp string `json:"timestamp"`
}

type auditRecorder func(ruleID, action, key, signal string, count int64)

type redactProcessor struct {
	logger              *zap.Logger
	cfg                 *Config
	httpClient          *http.Client
	refreshInterval     time.Duration
	requestTimeout      time.Duration
	auditEnabled        bool
	auditEndpoint       string
	auditTenantID       string
	auditAPIKey         string
	auditTimeout        time.Duration
	auditFlush          time.Duration
	auditEventsEnabled  bool
	auditEventsEndpoint string
	auditEventsMaxBatch int
	auditEventBufferMax int

	mu      sync.RWMutex
	policy  *compiledPolicy
	etag    string
	running bool

	auditMu      sync.Mutex
	auditRunning bool
	auditCounts  map[string]int64
	auditEvents  []auditEvent

	startOnce sync.Once
	stopOnce  sync.Once
	stopCh    chan struct{}
	doneCh    chan struct{}
	auditDone chan struct{}
}

var errPolicyNotModified = errors.New("policy not modified")

func newRedactProcessor(cfg component.Config, logger *zap.Logger) (*redactProcessor, error) {
	redactCfg, ok := cfg.(*Config)
	if !ok {
		return nil, errors.New("invalid redactprocessor config")
	}

	refreshInterval, err := parseDuration(redactCfg.PolicySource.RefreshInterval, 5*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("invalid policy refresh interval: %w", err)
	}
	requestTimeout, err := parseDuration(redactCfg.PolicySource.Timeout, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid policy timeout: %w", err)
	}
	auditFlush, err := parseDuration(redactCfg.Audit.FlushInterval, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid audit flush interval: %w", err)
	}
	auditTimeout, err := parseDuration(redactCfg.Audit.Timeout, 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("invalid audit timeout: %w", err)
	}

	rp := &redactProcessor{
		logger:              logger,
		cfg:                 redactCfg,
		httpClient:          &http.Client{},
		refreshInterval:     refreshInterval,
		requestTimeout:      requestTimeout,
		auditFlush:          auditFlush,
		auditTimeout:        auditTimeout,
		auditEventBufferMax: 5000,
		stopCh:              make(chan struct{}),
		doneCh:              make(chan struct{}),
		auditDone:           make(chan struct{}),
		auditCounts:         map[string]int64{},
		auditEvents:         []auditEvent{},
	}

	rp.configureAuditSink()

	localPolicy, localErr := buildPolicyFromConfig(redactCfg, logger)
	if localErr == nil {
		rp.setPolicy(localPolicy)
	}

	if strings.EqualFold(redactCfg.PolicySource.Mode, "aws") {
		if strings.TrimSpace(redactCfg.PolicySource.Endpoint) == "" {
			return nil, errors.New("policy_source.endpoint is required for aws mode")
		}
		ctx, cancel := context.WithTimeout(context.Background(), rp.requestTimeout)
		remotePolicy, etag, remoteErr := rp.fetchAndCompile(ctx)
		cancel()
		if remoteErr == nil {
			rp.setPolicy(remotePolicy)
			rp.setETag(etag)
			rp.logger.Info("loaded policy from control plane", zap.String("endpoint", rp.resolvePolicyEndpoint()))
		} else if localErr != nil {
			return nil, fmt.Errorf("failed to load policy from control plane: %w", remoteErr)
		} else {
			rp.logger.Warn("initial policy fetch failed, using local fallback", zap.Error(remoteErr))
		}
	} else if localErr != nil {
		return nil, localErr
	}

	if rp.activePolicy() == nil {
		return nil, errors.New("no policy available")
	}
	return rp, nil
}

func buildPolicyFromConfig(cfg *Config, logger *zap.Logger) (*compiledPolicy, error) {
	rules := cfg.Rules
	hmacSecrets := cfg.HMACSecrets

	if cfg.PolicySource.File != "" {
		policy, err := loadPolicyFromFile(cfg.PolicySource.File)
		if err != nil {
			logger.Warn("policy file load failed, falling back to inline rules", zap.String("path", cfg.PolicySource.File), zap.Error(err))
		} else {
			if len(policy.Rules) > 0 {
				rules = policy.Rules
			}
			if len(policy.HMACSecrets) > 0 {
				hmacSecrets = policy.HMACSecrets
			}
		}
	}

	return compilePolicy(rules, hmacSecrets)
}

func compilePolicy(rules []Rule, hmacSecrets map[string]string) (*compiledPolicy, error) {
	if len(rules) == 0 {
		return nil, errors.New("no redaction rules configured")
	}

	compiled := &compiledPolicy{
		dropKeys:           map[string]string{},
		tokenizeKeys:       map[string]tokenizeRule{},
		hmacSecrets:        map[string][]byte{},
		maskAttributeRules: map[string][]maskRule{},
		maskResourceRules:  map[string][]maskRule{},
		maskLogBodyRules:   []maskRule{},
	}

	for keyID, secret := range hmacSecrets {
		if secret == "" {
			continue
		}
		compiled.hmacSecrets[keyID] = []byte(secret)
	}

	for idx, rule := range rules {
		ruleID := ruleIdentifier(rule, idx)
		switch strings.ToLower(rule.Type) {
		case "drop_key":
			for _, key := range rule.MatchKeys {
				if key == "" {
					continue
				}
				compiled.dropKeys[key] = ruleID
			}
		case "mask_regex":
			if rule.Pattern == "" {
				return nil, fmt.Errorf("mask_regex rule missing pattern")
			}
			re, err := regexp.Compile(rule.Pattern)
			if err != nil {
				return nil, fmt.Errorf("invalid mask_regex pattern: %w", err)
			}
			compiledRule := maskRule{ruleID: ruleID, re: re, replacement: rule.Replacement}
			for _, field := range rule.Fields {
				switch {
				case field == "log.body":
					compiled.maskLogBodyRules = append(compiled.maskLogBodyRules, compiledRule)
				case strings.HasPrefix(field, "attributes."):
					key := strings.TrimPrefix(field, "attributes.")
					if key != "" {
						compiled.maskAttributeRules[key] = append(compiled.maskAttributeRules[key], compiledRule)
					}
				case strings.HasPrefix(field, "resource."):
					key := strings.TrimPrefix(field, "resource.")
					if key != "" {
						compiled.maskResourceRules[key] = append(compiled.maskResourceRules[key], compiledRule)
					}
				}
			}
		case "tokenize_hmac":
			if rule.KeyID == "" {
				return nil, fmt.Errorf("tokenize_hmac rule missing key_id")
			}
			if len(rule.MatchKeys) == 0 {
				return nil, fmt.Errorf("tokenize_hmac rule missing match_keys")
			}
			if _, ok := compiled.hmacSecrets[rule.KeyID]; !ok {
				return nil, fmt.Errorf("tokenize_hmac key_id not found: %s", rule.KeyID)
			}
			for _, key := range rule.MatchKeys {
				if key == "" {
					continue
				}
				compiled.tokenizeKeys[key] = tokenizeRule{keyID: rule.KeyID, ruleID: ruleID}
			}
		default:
			return nil, fmt.Errorf("unsupported rule type: %s", rule.Type)
		}
	}

	return compiled, nil
}

func (rp *redactProcessor) activePolicy() *compiledPolicy {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	return rp.policy
}

func (rp *redactProcessor) setPolicy(policy *compiledPolicy) {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	rp.policy = policy
}

func (rp *redactProcessor) setETag(etag string) {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	rp.etag = etag
}

func (rp *redactProcessor) getETag() string {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	return rp.etag
}

func (rp *redactProcessor) start(context.Context, component.Host) error {
	rp.startOnce.Do(func() {
		if strings.EqualFold(rp.cfg.PolicySource.Mode, "aws") {
			rp.mu.Lock()
			rp.running = true
			rp.mu.Unlock()
			go rp.refreshLoop()
		}
		if rp.auditEnabled {
			rp.auditMu.Lock()
			rp.auditRunning = true
			rp.auditMu.Unlock()
			go rp.auditLoop()
		}
	})
	return nil
}

func (rp *redactProcessor) shutdown(context.Context) error {
	rp.stopOnce.Do(func() {
		close(rp.stopCh)
		if rp.isRunning() {
			<-rp.doneCh
		}
		if rp.isAuditRunning() {
			<-rp.auditDone
		}
	})
	return nil
}

func (rp *redactProcessor) isRunning() bool {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	return rp.running
}

func (rp *redactProcessor) isAuditRunning() bool {
	rp.auditMu.Lock()
	defer rp.auditMu.Unlock()
	return rp.auditRunning
}

func (rp *redactProcessor) refreshLoop() {
	defer close(rp.doneCh)
	defer func() {
		rp.mu.Lock()
		rp.running = false
		rp.mu.Unlock()
	}()

	ticker := time.NewTicker(rp.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-rp.stopCh:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), rp.requestTimeout)
			policy, etag, err := rp.fetchAndCompile(ctx)
			cancel()
			if errors.Is(err, errPolicyNotModified) {
				continue
			}
			if err != nil {
				rp.logger.Warn("policy refresh failed, keeping last-known-good policy", zap.Error(err))
				continue
			}
			rp.setPolicy(policy)
			rp.setETag(etag)
			rp.logger.Info("policy refreshed from control plane")
		}
	}
}

func (rp *redactProcessor) configureAuditSink() {
	if !rp.cfg.Audit.Enabled {
		return
	}
	endpoint := strings.TrimSpace(rp.cfg.Audit.Endpoint)
	if endpoint == "" {
		rp.logger.Warn("audit sink enabled but endpoint is empty; disabling audit sink")
		return
	}
	rp.auditEnabled = true
	rp.auditEndpoint = endpoint
	rp.auditTenantID = strings.TrimSpace(rp.cfg.Audit.TenantID)
	rp.auditAPIKey = strings.TrimSpace(rp.cfg.Audit.APIKey)
	if rp.auditTenantID == "" {
		rp.auditTenantID = strings.TrimSpace(rp.cfg.PolicySource.TenantID)
	}
	if rp.auditAPIKey == "" {
		rp.auditAPIKey = strings.TrimSpace(rp.cfg.PolicySource.APIKey)
	}

	if rp.cfg.Audit.EventsEnabled {
		eventsEndpoint := strings.TrimSpace(rp.cfg.Audit.EventsEndpoint)
		if eventsEndpoint == "" {
			rp.logger.Warn("audit events enabled but events_endpoint is empty; disabling audit events")
		} else {
			rp.auditEventsEnabled = true
			rp.auditEventsEndpoint = eventsEndpoint
			rp.auditEventsMaxBatch = rp.cfg.Audit.EventsMaxBatch
			if rp.auditEventsMaxBatch <= 0 {
				rp.auditEventsMaxBatch = 200
			}
		}
	}
}

func (rp *redactProcessor) auditLoop() {
	defer close(rp.auditDone)
	defer func() {
		rp.auditMu.Lock()
		rp.auditRunning = false
		rp.auditMu.Unlock()
	}()

	ticker := time.NewTicker(rp.auditFlush)
	defer ticker.Stop()

	for {
		select {
		case <-rp.stopCh:
			ctx, cancel := context.WithTimeout(context.Background(), rp.auditTimeout)
			rp.flushAuditCounts(ctx)
			rp.flushAuditEvents(ctx)
			cancel()
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), rp.auditTimeout)
			rp.flushAuditCounts(ctx)
			rp.flushAuditEvents(ctx)
			cancel()
		}
	}
}

func (rp *redactProcessor) addAuditHits(hits map[string]int64) {
	if !rp.auditEnabled || len(hits) == 0 {
		return
	}
	rp.auditMu.Lock()
	defer rp.auditMu.Unlock()
	for ruleID, count := range hits {
		if strings.TrimSpace(ruleID) == "" || count <= 0 {
			continue
		}
		rp.auditCounts[ruleID] += count
	}
}

func (rp *redactProcessor) recordAuditEvent(ruleID, action, key, signal string, count int64) {
	if !rp.auditEventsEnabled {
		return
	}
	if strings.TrimSpace(ruleID) == "" || count <= 0 {
		return
	}
	event := auditEvent{
		RuleID:    ruleID,
		Action:    action,
		Key:       key,
		Signal:    signal,
		Count:     count,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	}
	rp.auditMu.Lock()
	defer rp.auditMu.Unlock()
	if len(rp.auditEvents) >= rp.auditEventBufferMax {
		rp.auditEvents = rp.auditEvents[1:]
	}
	rp.auditEvents = append(rp.auditEvents, event)
}

func (rp *redactProcessor) auditRecorder(signal string) auditRecorder {
	if !rp.auditEventsEnabled {
		return nil
	}
	return func(ruleID, action, key, signalOverride string, count int64) {
		s := signal
		if strings.TrimSpace(signalOverride) != "" {
			s = signalOverride
		}
		rp.recordAuditEvent(ruleID, action, key, s, count)
	}
}

func (rp *redactProcessor) flushAuditEvents(ctx context.Context) {
	if !rp.auditEventsEnabled {
		return
	}
	events := rp.drainAuditEvents()
	if len(events) == 0 {
		return
	}
	maxBatch := rp.auditEventsMaxBatch
	for i := 0; i < len(events); i += maxBatch {
		end := i + maxBatch
		if end > len(events) {
			end = len(events)
		}
		batch := events[i:end]
		if err := rp.postAuditEvents(ctx, batch); err != nil {
			rp.logger.Warn("failed to post audit events", zap.Int("count", len(batch)), zap.Error(err))
			rp.mergeAuditEvents(batch)
		}
	}
}

func (rp *redactProcessor) drainAuditEvents() []auditEvent {
	rp.auditMu.Lock()
	defer rp.auditMu.Unlock()
	if len(rp.auditEvents) == 0 {
		return nil
	}
	out := make([]auditEvent, len(rp.auditEvents))
	copy(out, rp.auditEvents)
	rp.auditEvents = nil
	return out
}

func (rp *redactProcessor) mergeAuditEvents(events []auditEvent) {
	if len(events) == 0 {
		return
	}
	rp.auditMu.Lock()
	defer rp.auditMu.Unlock()
	for _, ev := range events {
		if len(rp.auditEvents) >= rp.auditEventBufferMax {
			rp.auditEvents = rp.auditEvents[1:]
		}
		rp.auditEvents = append(rp.auditEvents, ev)
	}
}

func (rp *redactProcessor) flushAuditCounts(ctx context.Context) {
	if !rp.auditEnabled {
		return
	}
	batch := rp.drainAuditCounts()
	if len(batch) == 0 {
		return
	}
	failed := make(map[string]int64)
	for ruleID, count := range batch {
		if err := rp.postAuditCount(ctx, ruleID, count); err != nil {
			rp.logger.Warn("failed to post audit count", zap.String("rule_id", ruleID), zap.Int64("count", count), zap.Error(err))
			failed[ruleID] += count
		}
	}
	if len(failed) > 0 {
		rp.mergeAuditCounts(failed)
	}
}

func (rp *redactProcessor) drainAuditCounts() map[string]int64 {
	rp.auditMu.Lock()
	defer rp.auditMu.Unlock()
	if len(rp.auditCounts) == 0 {
		return nil
	}
	out := make(map[string]int64, len(rp.auditCounts))
	for k, v := range rp.auditCounts {
		out[k] = v
	}
	rp.auditCounts = make(map[string]int64)
	return out
}

func (rp *redactProcessor) mergeAuditCounts(counts map[string]int64) {
	rp.auditMu.Lock()
	defer rp.auditMu.Unlock()
	for ruleID, count := range counts {
		if strings.TrimSpace(ruleID) == "" || count <= 0 {
			continue
		}
		rp.auditCounts[ruleID] += count
	}
}

func (rp *redactProcessor) resolveAuditEndpoint() string {
	tenantID := strings.TrimSpace(rp.auditTenantID)
	if tenantID == "" {
		return rp.auditEndpoint
	}
	return strings.ReplaceAll(rp.auditEndpoint, "{tenant_id}", tenantID)
}

func (rp *redactProcessor) resolveAuditEventsEndpoint() string {
	tenantID := strings.TrimSpace(rp.auditTenantID)
	if tenantID == "" {
		return rp.auditEventsEndpoint
	}
	return strings.ReplaceAll(rp.auditEventsEndpoint, "{tenant_id}", tenantID)
}

func (rp *redactProcessor) postAuditCount(ctx context.Context, ruleID string, count int64) error {
	payload := map[string]any{
		"ruleId": ruleID,
		"count":  count,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rp.resolveAuditEndpoint(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if rp.auditAPIKey != "" {
		req.Header.Set("X-API-Key", rp.auditAPIKey)
		req.Header.Set("Authorization", "Bearer "+rp.auditAPIKey)
	}

	resp, err := rp.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("audit endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

func (rp *redactProcessor) postAuditEvents(ctx context.Context, events []auditEvent) error {
	if len(events) == 0 {
		return nil
	}
	payload := map[string]any{
		"events": events,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rp.resolveAuditEventsEndpoint(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if rp.auditAPIKey != "" {
		req.Header.Set("X-API-Key", rp.auditAPIKey)
		req.Header.Set("Authorization", "Bearer "+rp.auditAPIKey)
	}

	resp, err := rp.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("audit events endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

func (rp *redactProcessor) fetchAndCompile(ctx context.Context) (*compiledPolicy, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rp.resolvePolicyEndpoint(), nil)
	if err != nil {
		return nil, "", err
	}
	if apiKey := strings.TrimSpace(rp.cfg.PolicySource.APIKey); apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	if etag := strings.TrimSpace(rp.getETag()); etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := rp.httpClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return nil, rp.getETag(), errPolicyNotModified
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, "", fmt.Errorf("control plane returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	loadedPolicy, err := parsePolicyPayload(body)
	if err != nil {
		return nil, "", err
	}
	compiled, err := compilePolicy(loadedPolicy.Rules, loadedPolicy.HMACSecrets)
	if err != nil {
		return nil, "", err
	}

	etag := strings.TrimSpace(resp.Header.Get("ETag"))
	return compiled, etag, nil
}

func parsePolicyPayload(body []byte) (*policyFile, error) {
	var wrapped struct {
		Policy json.RawMessage `json:"policy"`
	}
	if err := json.Unmarshal(body, &wrapped); err == nil && len(wrapped.Policy) > 0 {
		var parsed policyFile
		if err := json.Unmarshal(wrapped.Policy, &parsed); err != nil {
			return nil, fmt.Errorf("failed to parse wrapped policy: %w", err)
		}
		return &parsed, nil
	}

	var parsedJSON policyFile
	if err := json.Unmarshal(body, &parsedJSON); err == nil && (len(parsedJSON.Rules) > 0 || len(parsedJSON.HMACSecrets) > 0) {
		return &parsedJSON, nil
	}

	var parsedYAML policyFile
	if err := yaml.Unmarshal(body, &parsedYAML); err == nil && (len(parsedYAML.Rules) > 0 || len(parsedYAML.HMACSecrets) > 0) {
		return &parsedYAML, nil
	}

	return nil, errors.New("control plane payload did not contain a valid policy")
}

func parseDuration(value string, fallback time.Duration) (time.Duration, error) {
	if strings.TrimSpace(value) == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, errors.New("duration must be > 0")
	}
	return d, nil
}

func ruleIdentifier(rule Rule, idx int) string {
	if strings.TrimSpace(rule.ID) != "" {
		return strings.TrimSpace(rule.ID)
	}
	ruleType := strings.TrimSpace(rule.Type)
	if ruleType == "" {
		ruleType = "rule"
	}
	return fmt.Sprintf("%s.%d", ruleType, idx+1)
}

func (rp *redactProcessor) resolvePolicyEndpoint() string {
	endpoint := strings.TrimSpace(rp.cfg.PolicySource.Endpoint)
	tenantID := strings.TrimSpace(rp.cfg.PolicySource.TenantID)
	if tenantID == "" {
		return endpoint
	}
	return strings.ReplaceAll(endpoint, "{tenant_id}", tenantID)
}

func loadPolicyFromFile(path string) (*policyFile, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var policy policyFile
	if err := yaml.Unmarshal(content, &policy); err != nil {
		return nil, err
	}
	return &policy, nil
}

func (p *compiledPolicy) applyResourceAttributes(attrs pcommon.Map, hits map[string]int64, recorder auditRecorder, signal string) {
	p.applyAttributeRules(attrs, p.maskResourceRules, hits, recorder, signal)
}

func (p *compiledPolicy) applyAttributeRules(attrs pcommon.Map, maskRules map[string][]maskRule, hits map[string]int64, recorder auditRecorder, signal string) {
	if attrs.Len() == 0 {
		return
	}

	for key, ruleID := range p.dropKeys {
		if attrs.Remove(key) {
			addRuleHit(hits, ruleID, 1)
			if recorder != nil {
				recorder(ruleID, "drop", key, signal, 1)
			}
		}
	}

	for key, tokenCfg := range p.tokenizeKeys {
		val, ok := attrs.Get(key)
		if !ok || val.Type() != pcommon.ValueTypeStr {
			continue
		}
		secret := p.hmacSecrets[tokenCfg.keyID]
		if len(secret) == 0 {
			continue
		}
		tokenized := hmacToken(secret, val.Str())
		if tokenized != val.Str() {
			addRuleHit(hits, tokenCfg.ruleID, 1)
			if recorder != nil {
				recorder(tokenCfg.ruleID, "tokenize", key, signal, 1)
			}
		}
		val.SetStr(tokenized)
	}

	for key, rules := range maskRules {
		val, ok := attrs.Get(key)
		if !ok || val.Type() != pcommon.ValueTypeStr {
			continue
		}
		val.SetStr(applyMaskRules(val.Str(), rules, hits, recorder, key, signal))
	}
}

func applyMaskRules(value string, rules []maskRule, hits map[string]int64, recorder auditRecorder, key, signal string) string {
	if value == "" || len(rules) == 0 {
		return value
	}
	masked := value
	for _, rule := range rules {
		matchCount := len(rule.re.FindAllStringIndex(masked, -1))
		if matchCount > 0 {
			addRuleHit(hits, rule.ruleID, int64(matchCount))
			if recorder != nil {
				recorder(rule.ruleID, "mask", key, signal, int64(matchCount))
			}
		}
		masked = rule.re.ReplaceAllString(masked, rule.replacement)
	}
	return masked
}

func addRuleHit(hits map[string]int64, ruleID string, count int64) {
	if hits == nil || strings.TrimSpace(ruleID) == "" || count <= 0 {
		return
	}
	hits[ruleID] += count
}

func hmacToken(secret []byte, value string) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}
