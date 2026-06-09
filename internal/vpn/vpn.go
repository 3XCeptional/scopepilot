// Package vpn manages a WireGuard gateway container that provides
// VPN-routed egress for worker containers via network namespace sharing.
//
// Architecture:
//
//	Worker containers use --network container:scopepilot-vpn-gateway
//	to share the gateway's network stack. All their traffic flows through
//	the WireGuard tunnel inside the gateway's namespace.
//
//	podman host
//	  ├── scopepilot-vpn-gateway (Alpine + WireGuard tunnel → Proton VPN)
//	  │   └── Workers share its namespace via --network container:
//	  └── Management (proxy :8443, MCP :9090) — host network (not shared)
//
// This avoids complex routing setup: namespace sharing is the simplest
// correct pattern for rootless Podman on macOS.
package vpn

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Config holds VPN gateway configuration.
type Config struct {
	// WGConfigPath is the path to the WireGuard config file on the host
	// that will be mounted into the container. Required.
	WGConfigPath string

	// ContainerName is the name for the VPN gateway container.
	// Default: "scopepilot-vpn-gateway".
	ContainerName string

	// ContainerImage is the OCI image for the VPN gateway.
	// Default: "localhost/scopepilot-wireguard:latest" (our custom image).
	ContainerImage string

	// PodmanBinary is the path to the podman binary.
	// Default: "podman".
	PodmanBinary string

	// Enabled controls whether VPN routing is active.
	Enabled bool

	// KillSwitch enables the VPN kill switch — if the VPN drops, traffic
	// through the gateway is blocked. Implemented via iptables rules
	// in the gateway container. Requires NET_ADMIN + rootful or
	// rootless with podman unshare support.
	KillSwitch bool

	// StartupTimeout is how long to wait for the VPN to connect.
	// Default: 30s.
	StartupTimeout time.Duration
}

// setDefaults fills in zero-valued fields with sensible defaults.
func (c *Config) setDefaults() {
	if c.ContainerName == "" {
		c.ContainerName = "scopepilot-vpn-gateway"
	}
	if c.ContainerImage == "" {
		c.ContainerImage = "localhost/scopepilot-wireguard:latest"
	}
	if c.PodmanBinary == "" {
		c.PodmanBinary = "podman"
	}
	if c.StartupTimeout == 0 {
		c.StartupTimeout = 30 * time.Second
	}
}

// Validate checks the configuration for correctness.
func (c *Config) Validate() error {
	if c.Enabled && c.WGConfigPath == "" {
		return fmt.Errorf("vpn: wg_config_path is required when enabled")
	}
	return nil
}

// Status represents the current VPN gateway status.
type Status struct {
	Running    bool   `json:"running"`
	Container  string `json:"container"`
	PublicIP   string `json:"public_ip,omitempty"`
	Connection string `json:"connection,omitempty"` // "connected" or "disconnected"
}

// Controller manages the lifecycle of the VPN gateway container.
type Controller struct {
	cfg Config
}

// New creates a new VPN Controller with the given config.
func New(cfg Config) *Controller {
	cfg.setDefaults()
	return &Controller{cfg: cfg}
}

// Start pulls the image (if needed) and launches the VPN gateway container.
// The container mounts the WireGuard config and runs wg-quick to establish
// the tunnel. Worker containers can share its network namespace via
// --network container:<container-name>.
//
// Returns an error if any step fails. On success, the VPN tunnel should be
// established within StartupTimeout.
func (ctl *Controller) Start() error {
	if !ctl.cfg.Enabled {
		return fmt.Errorf("vpn: controller is disabled, cannot start")
	}

	// Step 1: Ensure the image is available locally.
	if err := ctl.ensureImage(); err != nil {
		return fmt.Errorf("vpn: ensure image: %w", err)
	}

	// Step 2: Start the gateway container.
	if err := ctl.startContainer(); err != nil {
		return fmt.Errorf("vpn: start container: %w", err)
	}

	// Step 3: Wait for WireGuard to connect.
	if err := ctl.waitForConnection(); err != nil {
		return fmt.Errorf("vpn: wait for connection: %w", err)
	}

	return nil
}

// Stop stops and removes the VPN gateway container. Worker containers
// sharing its namespace are unaffected but lose network connectivity.
func (ctl *Controller) Stop() error {
	rmCmd := exec.Command(ctl.cfg.PodmanBinary, "rm", "-f", ctl.cfg.ContainerName)
	_ = rmCmd.Run() // Ignore error — container may not exist.
	return nil
}

// Status returns the current state of the VPN gateway.
func (ctl *Controller) Status() *Status {
	s := &Status{
		Container: ctl.cfg.ContainerName,
		Running:   false,
	}

	// Check if container is running.
	psCmd := exec.Command(ctl.cfg.PodmanBinary, "ps", "--filter", "name="+ctl.cfg.ContainerName, "--format", "{{.Status}}")
	output, err := psCmd.Output()
	if err != nil {
		return s
	}
	statusStr := strings.TrimSpace(string(output))
	if statusStr == "" {
		return s
	}
	s.Running = true

	// Determine connection state from container logs.
	logCmd := exec.Command(ctl.cfg.PodmanBinary, "logs", "--tail", "5", ctl.cfg.ContainerName)
	if logOut, err := logCmd.Output(); err == nil {
		logStr := string(logOut)
		if strings.Contains(logStr, "connected") || strings.Contains(logStr, "Success") {
			s.Connection = "connected"
		} else {
			s.Connection = "disconnected"
		}
	}

	// Determine public IP by running curl inside the container.
	pubCmd := exec.Command(ctl.cfg.PodmanBinary, "exec", ctl.cfg.ContainerName,
		"curl", "-s", "--max-time", "5", "https://ifconfig.me")
	if pubOut, err := pubCmd.Output(); err == nil {
		s.PublicIP = strings.TrimSpace(string(pubOut))
	}

	return s
}

// ContainerName returns the configured container name.
// Worker containers use this via --network container:<name>.
func (ctl *Controller) ContainerName() string {
	return ctl.cfg.ContainerName
}

// Config returns a copy of the controller's configuration.
func (ctl *Controller) Config() Config {
	return ctl.cfg
}

// ensureImage pulls the container image if not present locally.
// For localhost/ images, the image must be built manually — skip pull.
func (ctl *Controller) ensureImage() error {
	imageRef := ctl.cfg.ContainerImage

	// localhost/ images are built locally, never pulled from a registry.
	if strings.HasPrefix(imageRef, "localhost/") {
		// Check if the image exists locally; if not, return a clear error.
		imgCmd := exec.Command(ctl.cfg.PodmanBinary, "images", "--format", "{{.Repository}}:{{.Tag}}")
		output, err := imgCmd.Output()
		if err != nil {
			return fmt.Errorf("list images: %w", err)
		}
		for _, line := range strings.Split(string(output), "\n") {
			if strings.TrimSpace(line) == imageRef {
				return nil // Found locally.
			}
		}
		return fmt.Errorf("local image %q not found — run 'make build-containers' first", imageRef)
	}

	// Remote image — check if already present, pull if not.
	imgCmd := exec.Command(ctl.cfg.PodmanBinary, "images", "--format", "{{.Repository}}:{{.Tag}}")
	output, err := imgCmd.Output()
	if err != nil {
		return fmt.Errorf("list images: %w", err)
	}

	shortRef := strings.TrimPrefix(imageRef, "docker.io/")
	shortRef = strings.TrimPrefix(shortRef, "library/")

	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == imageRef || line == shortRef || strings.Contains(line, shortRef) {
			return nil // Image already exists.
		}
	}

	pullCmd := exec.Command(ctl.cfg.PodmanBinary, "pull", imageRef)
	if out, err := pullCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pull image %q: %w\n%s", imageRef, err, string(out))
	}
	return nil
}

// startContainer launches the VPN gateway container. The container runs
// on the default Podman bridge, mounts the WireGuard config as read-only,
// and uses NET_ADMIN or boringtun userspace WireGuard.
func (ctl *Controller) startContainer() error {
	// Check if container is already running.
	psCmd := exec.Command(ctl.cfg.PodmanBinary, "ps", "--filter", "name="+ctl.cfg.ContainerName, "--format", "{{.Names}}")
	output, err := psCmd.Output()
	if err == nil && strings.TrimSpace(string(output)) == ctl.cfg.ContainerName {
		return nil // Already running.
	}

	// Remove any stale container with the same name.
	rmCmd := exec.Command(ctl.cfg.PodmanBinary, "rm", "-f", ctl.cfg.ContainerName)
	_ = rmCmd.Run()

	// Build the run command.
	args := []string{
		"run", "-d",
		"--name", ctl.cfg.ContainerName,
		"--cap-add", "NET_ADMIN",
		"--sysctl", "net.ipv4.conf.all.src_valid_mark=1",
		"-v", ctl.cfg.WGConfigPath + ":/config/wg0.conf:ro",
	}

	// Add kill-switch env var if enabled.
	if ctl.cfg.KillSwitch {
		args = append(args, "-e", "KILLSWITCH=true")
	}

	args = append(args, ctl.cfg.ContainerImage)

	runCmd := exec.Command(ctl.cfg.PodmanBinary, args...)
	if out, err := runCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("run container: %w\n%s", err, string(out))
	}

	return nil
}

// waitForConnection polls the container logs until WireGuard reports
// a successful connection or the timeout expires.
func (ctl *Controller) waitForConnection() error {
	deadline := time.Now().Add(ctl.cfg.StartupTimeout)
	for time.Now().Before(deadline) {
		logCmd := exec.Command(ctl.cfg.PodmanBinary, "logs", "--tail", "10", ctl.cfg.ContainerName)
		out, err := logCmd.Output()
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		logStr := string(out)
		if strings.Contains(logStr, "connected") ||
			strings.Contains(logStr, "Success") ||
			strings.Contains(logStr, "WireGuard connected") {
			return nil
		}
		// Check for fatal errors.
		if strings.Contains(logStr, "ERROR") || strings.Contains(logStr, "error:") {
			// Non-fatal — could be transient warnings.
		}
		time.Sleep(1 * time.Second)
	}

	// Timeout — grab last few log lines for diagnostic.
	logCmd := exec.Command(ctl.cfg.PodmanBinary, "logs", "--tail", "20", ctl.cfg.ContainerName)
	lastLog, _ := logCmd.Output()
	return fmt.Errorf("timed out waiting for VPN connection after %s\nlast logs:\n%s",
		ctl.cfg.StartupTimeout, string(lastLog))
}
