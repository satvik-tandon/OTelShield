package redactprocessor

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

type maskRule struct {
	re          *regexp.Regexp
	replacement string
}

type compiledPolicy struct {
	dropKeys           map[string]struct{}
	tokenizeKeys       map[string]string
	hmacSecrets        map[string][]byte
	maskAttributeRules map[string][]maskRule
	maskResourceRules  map[string][]maskRule
	maskLogBodyRules   []maskRule
}

type policyFile struct {
	Rules       []Rule            `yaml:"rules"`
	HMACSecrets map[string]string `yaml:"hmac_secrets"`
}

type redactProcessor struct {
	policy *compiledPolicy
	logger *zap.Logger
}

func newRedactProcessor(cfg component.Config, logger *zap.Logger) (*redactProcessor, error) {
	redactCfg, ok := cfg.(*Config)
	if !ok {
		return nil, errors.New("invalid redactprocessor config")
	}
	policy, err := buildPolicy(redactCfg, logger)
	if err != nil {
		return nil, err
	}
	return &redactProcessor{policy: policy, logger: logger}, nil
}

func buildPolicy(cfg *Config, logger *zap.Logger) (*compiledPolicy, error) {
	rules := cfg.Rules
	hmacSecrets := cfg.HMACSecrets

	if strings.EqualFold(cfg.PolicySource.Mode, "local") && cfg.PolicySource.File != "" {
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

	if len(rules) == 0 {
		return nil, errors.New("no redaction rules configured")
	}

	compiled := &compiledPolicy{
		dropKeys:           map[string]struct{}{},
		tokenizeKeys:       map[string]string{},
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

	for _, rule := range rules {
		switch strings.ToLower(rule.Type) {
		case "drop_key":
			for _, key := range rule.MatchKeys {
				if key == "" {
					continue
				}
				compiled.dropKeys[key] = struct{}{}
			}
		case "mask_regex":
			if rule.Pattern == "" {
				return nil, fmt.Errorf("mask_regex rule missing pattern")
			}
			re, err := regexp.Compile(rule.Pattern)
			if err != nil {
				return nil, fmt.Errorf("invalid mask_regex pattern: %w", err)
			}
			compiledRule := maskRule{re: re, replacement: rule.Replacement}
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
				compiled.tokenizeKeys[key] = rule.KeyID
			}
		default:
			return nil, fmt.Errorf("unsupported rule type: %s", rule.Type)
		}
	}

	return compiled, nil
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

func (p *compiledPolicy) applyResourceAttributes(attrs pcommon.Map) {
	p.applyAttributeRules(attrs, p.maskResourceRules)
}

func (p *compiledPolicy) applyAttributeRules(attrs pcommon.Map, maskRules map[string][]maskRule) {
	if attrs.Len() == 0 {
		return
	}

	for key := range p.dropKeys {
		attrs.Remove(key)
	}

	for key, keyID := range p.tokenizeKeys {
		val, ok := attrs.Get(key)
		if !ok || val.Type() != pcommon.ValueTypeStr {
			continue
		}
		secret := p.hmacSecrets[keyID]
		if len(secret) == 0 {
			continue
		}
		val.SetStr(hmacToken(secret, val.Str()))
	}

	for key, rules := range maskRules {
		val, ok := attrs.Get(key)
		if !ok || val.Type() != pcommon.ValueTypeStr {
			continue
		}
		val.SetStr(applyMaskRules(val.Str(), rules))
	}
}

func applyMaskRules(value string, rules []maskRule) string {
	if value == "" || len(rules) == 0 {
		return value
	}
	masked := value
	for _, rule := range rules {
		masked = rule.re.ReplaceAllString(masked, rule.replacement)
	}
	return masked
}

func hmacToken(secret []byte, value string) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}
