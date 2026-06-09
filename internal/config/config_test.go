package config

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestValidateGlobalDefaults(t *testing.T) {
	tests := []struct {
		name    string
		cfg     GlobalConfig
		wantErr bool
	}{
		{
			name: "valid defaults",
			cfg: GlobalConfig{
				Defaults: DefaultsConfig{
					RequestsPerSecondPerHost: 2,
					MaxConcurrency:           4,
					MaxResponseBytes:         5242880,
					AllowedSchemes:           []string{"https"},
					AllowedPorts:             []int{443},
				},
			},
			wantErr: false,
		},
		{
			name: "rps too high",
			cfg: GlobalConfig{
				Defaults: DefaultsConfig{
					RequestsPerSecondPerHost: 100,
					MaxConcurrency:           4,
					MaxResponseBytes:         5242880,
				},
			},
			wantErr: true,
		},
		{
			name: "invalid scheme",
			cfg: GlobalConfig{
				Defaults: DefaultsConfig{
					RequestsPerSecondPerHost: 2,
					MaxConcurrency:           4,
					MaxResponseBytes:         5242880,
					AllowedSchemes:           []string{"ftp"},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateProgramConfig(t *testing.T) {
	validProg := ProgramConfig{
		ID:               "test-program",
		Name:             "Test Program",
		AuthorizationRef: "policy-url",
		NetworkPolicy: NetworkPolicyConfig{
			VPN:                    "permitted",
			StableSourceIPRequired: false,
		},
		Limits: LimitsConfig{
			RequestsPerSecondPerHost: 2,
			MaxConcurrency:           4,
			MaxResponseBytes:         5242880,
			AllowedSchemes:           []string{"https"},
			AllowedPorts:             []int{443},
			MaxCrawlDepth:            3,
		},
		Scope: ScopeConfig{
			Include: []ScopeRule{
				{Type: "exact_host", Value: "app.example.com"},
				{Type: "wildcard_host", Value: "*.example.com"},
			},
		},
	}

	t.Run("valid program", func(t *testing.T) {
		if err := validProg.Validate(); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("missing authorization", func(t *testing.T) {
		p := validProg
		p.AuthorizationRef = ""
		if err := p.Validate(); err == nil {
			t.Error("expected error for missing authorization")
		}
	})

	t.Run("invalid vpn policy", func(t *testing.T) {
		p := validProg
		p.NetworkPolicy.VPN = "maybe"
		if err := p.Validate(); err == nil {
			t.Error("expected error for invalid VPN policy")
		}
	})

	t.Run("no scope includes", func(t *testing.T) {
		p := validProg
		p.Scope.Include = nil
		if err := p.Validate(); err == nil {
			t.Error("expected error for empty scope includes")
		}
	})

	t.Run("invalid scope rule type", func(t *testing.T) {
		p := validProg
		p.Scope.Include = append(p.Scope.Include, ScopeRule{Type: "unknown", Value: "test"})
		if err := p.Validate(); err == nil {
			t.Error("expected error for unknown scope rule type")
		}
	})
}

func TestValidateScopeRule(t *testing.T) {
	tests := []struct {
		name    string
		rule    ScopeRule
		wantErr bool
	}{
		{"valid exact_host", ScopeRule{Type: "exact_host", Value: "app.example.com"}, false},
		{"valid wildcard_host", ScopeRule{Type: "wildcard_host", Value: "*.example.com"}, false},
		{"valid path_prefix", ScopeRule{Type: "path_prefix", Value: "/logout", Host: "app.example.com"}, false},
		{"valid CIDR", ScopeRule{Type: "cidr", Value: "10.0.0.0/8"}, false},
		{"exact_host with IP", ScopeRule{Type: "exact_host", Value: "1.2.3.4"}, true},
		{"exact_host with scheme", ScopeRule{Type: "exact_host", Value: "https://app.example.com"}, true},
		{"exact_host with port", ScopeRule{Type: "exact_host", Value: "app.example.com:443"}, true},
		{"wildcard no star", ScopeRule{Type: "wildcard_host", Value: "example.com"}, true},
		{"path_prefix no slash", ScopeRule{Type: "path_prefix", Value: "logout", Host: "app.example.com"}, true},
		{"invalid CIDR", ScopeRule{Type: "cidr", Value: "not-a-cidr"}, true},
		{"exact_host empty", ScopeRule{Type: "exact_host", Value: ""}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateScopeRule(tt.rule)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateScopeRule() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfigFromYAML(t *testing.T) {
	yamlData := `
programs:
  - id: example-program
    name: Example Program
    authorization_reference: "https://example.com/policy"
    active_testing_enabled: false
    network_policy:
      vpn: permitted
      stable_source_ip_required: false
    limits:
      requests_per_second_per_host: 2
      max_concurrency: 4
      max_response_bytes: 5242880
      allowed_schemes: ["https"]
      allowed_ports: [443]
      max_crawl_depth: 3
    scope:
      include:
        - type: exact_host
          value: app.example.com
        - type: wildcard_host
          value: "*.example.com"
      exclude:
        - type: exact_host
          value: status.example.com
        - type: path_prefix
          host: app.example.com
          value: /logout
    restrictions:
      automated_scanning: permitted
      historical_url_collection: permitted
      subdomain_enumeration: permitted
global:
  defaults:
    requests_per_second_per_host: 2
    max_concurrency: 4
    max_response_bytes: 5242880
    allowed_schemes: ["https"]
    allowed_ports: [443]
    dry_run: true
  log_level: info
  log_format: json
`

	var cfg Config
	if err := yaml.Unmarshal([]byte(yamlData), &cfg); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validation failed: %v", err)
	}
	if len(cfg.Programs) != 1 {
		t.Fatalf("expected 1 program, got %d", len(cfg.Programs))
	}
	prog := cfg.Programs[0]
	if prog.ID != "example-program" {
		t.Errorf("expected id example-program, got %s", prog.ID)
	}
	if len(prog.Scope.Include) != 2 {
		t.Errorf("expected 2 scope includes, got %d", len(prog.Scope.Include))
	}
	if len(prog.Scope.Exclude) != 2 {
		t.Errorf("expected 2 scope excludes, got %d", len(prog.Scope.Exclude))
	}
}

func TestDuplicateProgramID(t *testing.T) {
	cfg := Config{
		Programs: []ProgramConfig{
			{ID: "prog1", AuthorizationRef: "ref", NetworkPolicy: NetworkPolicyConfig{VPN: "permitted"},
				Limits: LimitsConfig{RequestsPerSecondPerHost: 2, MaxConcurrency: 4, MaxResponseBytes: 1024},
				Scope:  ScopeConfig{Include: []ScopeRule{{Type: "exact_host", Value: "example.com"}}}},
			{ID: "prog1", AuthorizationRef: "ref2", NetworkPolicy: NetworkPolicyConfig{VPN: "permitted"},
				Limits: LimitsConfig{RequestsPerSecondPerHost: 2, MaxConcurrency: 4, MaxResponseBytes: 1024},
				Scope:  ScopeConfig{Include: []ScopeRule{{Type: "exact_host", Value: "example2.com"}}}},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for duplicate program ID")
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func TestGlobalVPNValidation(t *testing.T) {
	tests := []struct {
		name    string
		vpn     GlobalVPNConfig
		wantErr bool
	}{
		{
			name:    "vpn disabled no config required",
			vpn:     GlobalVPNConfig{Enabled: false},
			wantErr: false,
		},
		{
			name:    "vpn enabled requires wg_config_path",
			vpn:     GlobalVPNConfig{Enabled: true, WGConfigPath: ""},
			wantErr: true,
		},
		{
			name:    "vpn enabled with config is valid",
			vpn:     GlobalVPNConfig{Enabled: true, WGConfigPath: "/etc/wireguard/wg0.conf"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := GlobalConfig{
				Defaults: DefaultsConfig{
					RequestsPerSecondPerHost: 2,
					MaxConcurrency:           4,
					MaxResponseBytes:         5242880,
				},
				VPN: tt.vpn,
			}
			err := g.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}
