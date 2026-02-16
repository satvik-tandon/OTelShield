package redactprocessor

type PolicySource struct {
	Mode            string `mapstructure:"mode" yaml:"mode" json:"mode"`
	File            string `mapstructure:"file" yaml:"file" json:"file"`
	Endpoint        string `mapstructure:"endpoint" yaml:"endpoint" json:"endpoint"`
	RefreshInterval string `mapstructure:"refresh_interval" yaml:"refresh_interval" json:"refresh_interval"`
	Timeout         string `mapstructure:"timeout" yaml:"timeout" json:"timeout"`
	TenantID        string `mapstructure:"tenant_id" yaml:"tenant_id" json:"tenant_id"`
	APIKey          string `mapstructure:"api_key" yaml:"api_key" json:"api_key"`
}

type AuditSink struct {
	Enabled       bool   `mapstructure:"enabled" yaml:"enabled" json:"enabled"`
	Endpoint      string `mapstructure:"endpoint" yaml:"endpoint" json:"endpoint"`
	TenantID      string `mapstructure:"tenant_id" yaml:"tenant_id" json:"tenant_id"`
	APIKey        string `mapstructure:"api_key" yaml:"api_key" json:"api_key"`
	FlushInterval string `mapstructure:"flush_interval" yaml:"flush_interval" json:"flush_interval"`
	Timeout       string `mapstructure:"timeout" yaml:"timeout" json:"timeout"`
}

type Rule struct {
	ID          string   `mapstructure:"id" yaml:"id" json:"id"`
	Type        string   `mapstructure:"type" yaml:"type" json:"type"`
	MatchKeys   []string `mapstructure:"match_keys" yaml:"match_keys" json:"match_keys"`
	Fields      []string `mapstructure:"fields" yaml:"fields" json:"fields"`
	Pattern     string   `mapstructure:"pattern" yaml:"pattern" json:"pattern"`
	Replacement string   `mapstructure:"replacement" yaml:"replacement" json:"replacement"`
	KeyID       string   `mapstructure:"key_id" yaml:"key_id" json:"key_id"`
}

type Config struct {
	PolicySource PolicySource      `mapstructure:"policy_source" yaml:"policy_source" json:"policy_source"`
	Audit        AuditSink         `mapstructure:"audit" yaml:"audit" json:"audit"`
	Rules        []Rule            `mapstructure:"rules" yaml:"rules" json:"rules"`
	HMACSecrets  map[string]string `mapstructure:"hmac_secrets" yaml:"hmac_secrets" json:"hmac_secrets"`
}
