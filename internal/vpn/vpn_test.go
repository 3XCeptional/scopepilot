package vpn

import (
	"testing"
	"time"
)

func TestConfigDefaults(t *testing.T) {
	cfg := Config{Enabled: true, WGConfigPath: "/path/to/wg.conf"}
	cfg.setDefaults()

	if cfg.ContainerName != "scopepilot-vpn-gateway" {
		t.Errorf("expected default container name, got %q", cfg.ContainerName)
	}
	if cfg.ContainerImage != "localhost/scopepilot-wireguard:latest" {
		t.Errorf("expected default image, got %q", cfg.ContainerImage)
	}
	if cfg.PodmanBinary != "podman" {
		t.Errorf("expected default podman binary, got %q", cfg.PodmanBinary)
	}
	if cfg.StartupTimeout != 30*time.Second {
		t.Errorf("expected default startup timeout 30s, got %v", cfg.StartupTimeout)
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name:    "disabled requires no path",
			cfg:     Config{Enabled: false},
			wantErr: false,
		},
		{
			name:    "enabled requires wg config path",
			cfg:     Config{Enabled: true},
			wantErr: true,
		},
		{
			name:    "enabled with path is valid",
			cfg:     Config{Enabled: true, WGConfigPath: "/etc/wireguard/wg0.conf"},
			wantErr: false,
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

func TestNew(t *testing.T) {
	ctl := New(Config{Enabled: true, WGConfigPath: "/etc/wireguard/wg0.conf"})
	if ctl == nil {
		t.Fatal("New() returned nil")
	}
	if ctl.ContainerName() != "scopepilot-vpn-gateway" {
		t.Errorf("unexpected container name: %q", ctl.ContainerName())
	}
}

func TestStartDisabled(t *testing.T) {
	ctl := New(Config{Enabled: false})
	err := ctl.Start()
	if err == nil {
		t.Error("expected error when disabled, got nil")
	}
}

func TestConfigCopied(t *testing.T) {
	orig := Config{
		Enabled:        true,
		WGConfigPath:   "/etc/wireguard/wg0.conf",
		ContainerName:  "custom-vpn",
		ContainerImage: "custom/wireguard:1.0",
		PodmanBinary:   "/usr/local/bin/podman",
		KillSwitch:     true,
		StartupTimeout: 15 * time.Second,
	}
	ctl := New(orig)
	got := ctl.Config()

	if got.ContainerName != "custom-vpn" {
		t.Errorf("expected custom-vpn, got %q", got.ContainerName)
	}
	if got.ContainerImage != "custom/wireguard:1.0" {
		t.Errorf("expected custom image, got %q", got.ContainerImage)
	}
	if got.PodmanBinary != "/usr/local/bin/podman" {
		t.Errorf("expected custom podman path, got %q", got.PodmanBinary)
	}
	if !got.KillSwitch {
		t.Error("expected KillSwitch to be true")
	}
	if got.StartupTimeout != 15*time.Second {
		t.Errorf("expected timeout 15s, got %v", got.StartupTimeout)
	}
}

func TestDefaultsPreserveExplicit(t *testing.T) {
	cfg := Config{
		Enabled:       true,
		WGConfigPath:  "/path/to/wg.conf",
		ContainerName: "my-gateway",
	}
	cfg.setDefaults()

	if cfg.ContainerName != "my-gateway" {
		t.Errorf("explicit container name should be preserved, got %q", cfg.ContainerName)
	}
	if cfg.PodmanBinary != "podman" {
		t.Errorf("default podman binary should be set, got %q", cfg.PodmanBinary)
	}
}

func TestStatusDefaults(t *testing.T) {
	ctl := New(Config{Enabled: false})
	s := ctl.Status()
	if s.Running {
		t.Error("expected status.Running to be false")
	}
	if s.Container != "scopepilot-vpn-gateway" {
		t.Errorf("expected default container name in status, got %q", s.Container)
	}
}

func TestContainerName(t *testing.T) {
	ctl := New(Config{
		Enabled:       true,
		WGConfigPath:  "/etc/wireguard/wg0.conf",
		ContainerName: "custom-gateway",
	})
	if ctl.ContainerName() != "custom-gateway" {
		t.Errorf("expected custom-gateway, got %q", ctl.ContainerName())
	}
}
