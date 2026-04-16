package parser

import (
	"testing"

	"github.com/tttturtle-russ/clawsan/internal/types"
)

func TestParseConfig_Vulnerable(t *testing.T) {
	cfg, err := ParseConfig("../../testdata/vulnerable-config")
	if err != nil {
		t.Fatalf("ParseConfig failed: %v", err)
	}
	if cfg.Gateway.Bind != "lan" {
		t.Errorf("expected gateway.bind=lan, got %s", cfg.Gateway.Bind)
	}
	if !cfg.Gateway.ControlUi.DangerouslyDisableDeviceAuth {
		t.Error("expected gateway.controlUi.dangerouslyDisableDeviceAuth=true")
	}
	if cfg.Gateway.Tailscale.Mode != "funnel" {
		t.Errorf("expected gateway.tailscale.mode=funnel, got %s", cfg.Gateway.Tailscale.Mode)
	}
	if cfg.Tools.Exec.Host != "node" {
		t.Errorf("expected tools.exec.host=node, got %s", cfg.Tools.Exec.Host)
	}
}

func TestParseConfig_Clean(t *testing.T) {
	cfg, err := ParseConfig("../../testdata/clean-config")
	if err != nil {
		t.Fatalf("ParseConfig failed: %v", err)
	}
	if cfg.Gateway.Bind != "loopback" {
		t.Errorf("expected gateway.bind=loopback, got %s", cfg.Gateway.Bind)
	}
	if cfg.Gateway.Auth.Mode != "password" {
		t.Errorf("expected gateway.auth.mode=password, got %s", cfg.Gateway.Auth.Mode)
	}
	if cfg.Tools.Exec.Security != "allowlist" {
		t.Errorf("expected tools.exec.security=allowlist, got %s", cfg.Tools.Exec.Security)
	}
}

func TestParseConfig_MissingFile(t *testing.T) {
	_, err := ParseConfig("/nonexistent/path")
	if err == nil {
		t.Error("expected error for missing config file, got nil")
	}
}

func TestOpenClawConfig_Fields(t *testing.T) {
	cfg := types.OpenClawConfig{}
	_ = cfg.Gateway.ControlUi.DangerouslyDisableDeviceAuth
	_ = cfg.Gateway.Bind
	_ = cfg.Gateway.Auth.Token
	_ = cfg.Gateway.Auth.Mode
	_ = cfg.Tools.Exec.Host
}
