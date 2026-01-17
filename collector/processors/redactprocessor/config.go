package redactprocessor

type PolicySource struct {
	Mode     string `mapstructure:"mode"`
	File     string `mapstructure:"file"`
	Endpoint string `mapstructure:"endpoint"`
}

type Rule struct {
	Type        string   `mapstructure:"type"`
	MatchKeys   []string `mapstructure:"match_keys"`
	Fields      []string `mapstructure:"fields"`
	Pattern     string   `mapstructure:"pattern"`
	Replacement string   `mapstructure:"replacement"`
	KeyID       string   `mapstructure:"key_id"`
}

type Config struct {
	PolicySource PolicySource      `mapstructure:"policy_source"`
	Rules        []Rule            `mapstructure:"rules"`
	HMACSecrets  map[string]string `mapstructure:"hmac_secrets"`
}
