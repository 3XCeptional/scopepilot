// Package config provides configuration schema, validation, and loading for the
// pentest automation platform. All configuration is validated against a strict
// schema before use.
package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the root platform configuration.
type Config struct {
	Programs []ProgramConfig `yaml:"programs" json:"programs"`
	Global   GlobalConfig    `yaml:"global" json:"global"`
}

// GlobalConfig holds platform-wide settings.
type GlobalConfig struct {
	KillSwitch KillSwitchConfig `yaml:"kill_switch" json:"kill_switch"`
	Defaults   DefaultsConfig   `yaml:"defaults" json:"defaults"`
	Audit      AuditConfig      `yaml:"audit" json:"audit"`
	VPN        GlobalVPNConfig  `yaml:"vpn" json:"vpn"`
	Sandbox    SandboxConfig    `yaml:"sandbox" json:"sandbox"`
	LogLevel   string           `yaml:"log_level" json:"log_level"`
	LogFormat  string           `yaml:"log_format" json:"log_format"` // json or text
}

// KillSwitchConfig controls the global kill switch.
type KillSwitchConfig struct {
	Enabled     bool   `yaml:"enabled" json:"enabled"`
	ActivatedBy string `yaml:"activated_by" json:"activated_by"`
	ActivatedAt string `yaml:"activated_at" json:"activated_at"`
}

// DefaultsConfig holds default limits for all programs.
type DefaultsConfig struct {
	RequestsPerSecondPerHost int      `yaml:"requests_per_second_per_host" json:"requests_per_second_per_host"`
	MaxConcurrency           int      `yaml:"max_concurrency" json:"max_concurrency"`
	MaxResponseBytes         int64    `yaml:"max_response_bytes" json:"max_response_bytes"`
	AllowedSchemes           []string `yaml:"allowed_schemes" json:"allowed_schemes"`
	AllowedPorts             []int    `yaml:"allowed_ports" json:"allowed_ports"`
	DryRun                   bool     `yaml:"dry_run" json:"dry_run"`
}

// AuditConfig controls audit logging behavior.
type AuditConfig struct {
	Enabled       bool `yaml:"enabled" json:"enabled"`
	RetainDays    int  `yaml:"retain_days" json:"retain_days"`
	RedactSecrets bool `yaml:"redact_secrets" json:"redact_secrets"`
}

// GlobalVPNConfig is the global VPN policy for worker container egress.
// When enabled, the VPN controller starts a WireGuard gateway container
// and worker containers share its network namespace (--network container:)
// for VPN-routed egress. Management interfaces stay on the host network.
type GlobalVPNConfig struct {
	Enabled         bool   `yaml:"enabled" json:"enabled"`               // Enable VPN gateway
	Country         string `yaml:"country" json:"country"`               // Preferred VPN server country
	Server          string `yaml:"server" json:"server"`                 // Specific VPN server name
	WGConfigPath    string `yaml:"wg_config_path" json:"wg_config_path"` // Host path to WireGuard config file (required when enabled)
	ContainerName   string `yaml:"container_name" json:"container_name"` // Podman container name override
	ContainerImage  string `yaml:"container_image" json:"container_image"` // OCI image override
	KillSwitch      bool   `yaml:"kill_switch" json:"kill_switch"`       // Block traffic if VPN drops
	PodmanBinary    string `yaml:"podman_binary" json:"podman_binary"`   // Path to podman binary
}

// SandboxConfig controls the malware sandbox.
type SandboxConfig struct {
	MaxFileSize        int64   `yaml:"max_file_size" json:"max_file_size"`
	MaxArchiveDepth    int     `yaml:"max_archive_depth" json:"max_archive_depth"`
	MaxDecompressRatio float64 `yaml:"max_decompress_ratio" json:"max_decompress_ratio"`
	TimeoutSeconds     int     `yaml:"timeout_seconds" json:"timeout_seconds"`
}

// ProgramConfig defines a single bug-bounty program.
type ProgramConfig struct {
	ID                   string              `yaml:"id" json:"id"`
	Name                 string              `yaml:"name" json:"name"`
	AuthorizationRef     string              `yaml:"authorization_reference" json:"authorization_reference"`
	ActiveTestingEnabled bool                `yaml:"active_testing_enabled" json:"active_testing_enabled"`
	KillSwitch           KillSwitchConfig    `yaml:"kill_switch" json:"kill_switch"`
	NetworkPolicy        NetworkPolicyConfig `yaml:"network_policy" json:"network_policy"`
	Limits               LimitsConfig        `yaml:"limits" json:"limits"`
	Scope                ScopeConfig         `yaml:"scope" json:"scope"`
	Restrictions         RestrictionsConfig  `yaml:"restrictions" json:"restrictions"`
	Status               string              `yaml:"status" json:"status"` // active, paused, completed
}

// NetworkPolicyConfig defines VPN and network requirements.
type NetworkPolicyConfig struct {
	VPN                    string `yaml:"vpn" json:"vpn"` // required, permitted, prohibited
	StableSourceIPRequired bool   `yaml:"stable_source_ip_required" json:"stable_source_ip_required"`
}

// LimitsConfig defines per-program rate and request limits.
type LimitsConfig struct {
	RequestsPerSecondPerHost int      `yaml:"requests_per_second_per_host" json:"requests_per_second_per_host"`
	MaxConcurrency           int      `yaml:"max_concurrency" json:"max_concurrency"`
	MaxResponseBytes         int64    `yaml:"max_response_bytes" json:"max_response_bytes"`
	AllowedSchemes           []string `yaml:"allowed_schemes" json:"allowed_schemes"`
	AllowedPorts             []int    `yaml:"allowed_ports" json:"allowed_ports"`
	MaxRequestsPerJob        int      `yaml:"max_requests_per_job" json:"max_requests_per_job"`
	MaxCrawlDepth            int      `yaml:"max_crawl_depth" json:"max_crawl_depth"`
}

// ScopeConfig defines what is in and out of scope.
type ScopeConfig struct {
	Include []ScopeRule `yaml:"include" json:"include"`
	Exclude []ScopeRule `yaml:"exclude" json:"exclude"`
}

// ScopeRule defines a single scope rule.
type ScopeRule struct {
	Type  string `yaml:"type" json:"type"` // exact_host, wildcard_host, path_prefix, cidr
	Value string `yaml:"value" json:"value"`
	Host  string `yaml:"host" json:"host"` // optional, for path_prefix rules
}

// RestrictionsConfig defines program-specific restrictions.
type RestrictionsConfig struct {
	AutomatedScanning       string `yaml:"automated_scanning" json:"automated_scanning"` // permitted, prohibited, limited
	HistoricalURLCollection string `yaml:"historical_url_collection" json:"historical_url_collection"`
	SubdomainEnumeration    string `yaml:"subdomain_enumeration" json:"subdomain_enumeration"`
	Notes                   string `yaml:"notes" json:"notes"`
}

// Validate checks the configuration for correctness and safety.
func (c *Config) Validate() error {
	if err := c.Global.Validate(); err != nil {
		return fmt.Errorf("global config: %w", err)
	}
	seenIDs := make(map[string]bool)
	for i, prog := range c.Programs {
		if prog.ID == "" {
			return fmt.Errorf("program[%d]: id is required", i)
		}
		if seenIDs[prog.ID] {
			return fmt.Errorf("program[%d]: duplicate id %q", i, prog.ID)
		}
		seenIDs[prog.ID] = true
		if err := prog.Validate(); err != nil {
			return fmt.Errorf("program %q: %w", prog.ID, err)
		}
	}
	return nil
}

// Validate validates global configuration.
func (g *GlobalConfig) Validate() error {
	if g.Defaults.RequestsPerSecondPerHost < 1 || g.Defaults.RequestsPerSecondPerHost > 50 {
		return fmt.Errorf("defaults.requests_per_second_per_host must be 1-50, got %d", g.Defaults.RequestsPerSecondPerHost)
	}
	if g.Defaults.MaxConcurrency < 1 || g.Defaults.MaxConcurrency > 20 {
		return fmt.Errorf("defaults.max_concurrency must be 1-20, got %d", g.Defaults.MaxConcurrency)
	}
	if g.Defaults.MaxResponseBytes < 1024 || g.Defaults.MaxResponseBytes > 50*1024*1024 {
		return fmt.Errorf("defaults.max_response_bytes must be 1024-52428800, got %d", g.Defaults.MaxResponseBytes)
	}
	for _, scheme := range g.Defaults.AllowedSchemes {
		if scheme != "http" && scheme != "https" {
			return fmt.Errorf("defaults.allowed_schemes: unsupported scheme %q", scheme)
		}
	}
	for _, port := range g.Defaults.AllowedPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("defaults.allowed_ports: invalid port %d", port)
		}
	}
	if g.LogLevel != "" && g.LogLevel != "debug" && g.LogLevel != "info" && g.LogLevel != "warn" && g.LogLevel != "error" {
		return fmt.Errorf("log_level must be debug, info, warn, or error")
	}
	if g.VPN.Enabled && g.VPN.WGConfigPath == "" {
		return fmt.Errorf("vpn.wg_config_path is required when vpn is enabled")
	}
	return nil
}

// Validate validates a single program configuration.
func (p *ProgramConfig) Validate() error {
	if p.AuthorizationRef == "" {
		return fmt.Errorf("authorization_reference is required")
	}
	if p.NetworkPolicy.VPN != "required" && p.NetworkPolicy.VPN != "permitted" && p.NetworkPolicy.VPN != "prohibited" {
		return fmt.Errorf("network_policy.vpn must be required, permitted, or prohibited, got %q", p.NetworkPolicy.VPN)
	}
	if p.Limits.RequestsPerSecondPerHost < 1 || p.Limits.RequestsPerSecondPerHost > 50 {
		return fmt.Errorf("limits.requests_per_second_per_host must be 1-50, got %d", p.Limits.RequestsPerSecondPerHost)
	}
	if p.Limits.MaxConcurrency < 1 || p.Limits.MaxConcurrency > 20 {
		return fmt.Errorf("limits.max_concurrency must be 1-20, got %d", p.Limits.MaxConcurrency)
	}
	if p.Limits.MaxCrawlDepth < 0 || p.Limits.MaxCrawlDepth > 20 {
		return fmt.Errorf("limits.max_crawl_depth must be 0-20, got %d", p.Limits.MaxCrawlDepth)
	}
	for _, scheme := range p.Limits.AllowedSchemes {
		if scheme != "http" && scheme != "https" {
			return fmt.Errorf("limits.allowed_schemes: unsupported scheme %q", scheme)
		}
	}
	for _, port := range p.Limits.AllowedPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("limits.allowed_ports: invalid port %d", port)
		}
	}
	if len(p.Scope.Include) == 0 {
		return fmt.Errorf("scope.include must have at least one rule")
	}
	for i, rule := range p.Scope.Include {
		if err := validateScopeRule(rule); err != nil {
			return fmt.Errorf("scope.include[%d]: %w", i, err)
		}
	}
	for i, rule := range p.Scope.Exclude {
		if err := validateScopeRule(rule); err != nil {
			return fmt.Errorf("scope.exclude[%d]: %w", i, err)
		}
	}
	return nil
}

func validateScopeRule(r ScopeRule) error {
	switch r.Type {
	case "exact_host":
		return validateHost(r.Value)
	case "wildcard_host":
		return validateWildcardHost(r.Value)
	case "path_prefix":
		if r.Value == "" {
			return fmt.Errorf("value is required for path_prefix")
		}
		if !strings.HasPrefix(r.Value, "/") {
			return fmt.Errorf("path_prefix value must start with /")
		}
		return validateHost(r.Host)
	case "cidr":
		return validateCIDR(r.Value)
	default:
		return fmt.Errorf("unknown scope rule type %q", r.Type)
	}
}

func validateHost(host string) error {
	if host == "" {
		return fmt.Errorf("host is empty")
	}
	if ip := net.ParseIP(host); ip != nil {
		return fmt.Errorf("host %q is an IP address, not a hostname", host)
	}
	if strings.Contains(host, "://") {
		return fmt.Errorf("host %q contains a scheme", host)
	}
	// Check for port
	if _, _, err := net.SplitHostPort(host); err == nil {
		return fmt.Errorf("host %q contains a port", host)
	}
	// Basic hostname validation
	if _, err := url.Parse("//" + host); err != nil {
		return fmt.Errorf("invalid hostname %q: %w", host, err)
	}
	return nil
}

func validateWildcardHost(host string) error {
	if !strings.HasPrefix(host, "*.") {
		return fmt.Errorf("wildcard_host must start with '*.'")
	}
	return validateHost(host[2:])
}

func validateCIDR(cidr string) error {
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR %q: %v", cidr, err)
	}
	return nil
}

// Load parses YAML configuration from raw bytes into a Config struct.
func Load(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("yaml parse error: %w", err)
	}
	return &cfg, nil
}
