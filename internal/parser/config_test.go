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
	if cfg.Commands.UseAccessGroups == nil || *cfg.Commands.UseAccessGroups {
		t.Fatal("expected commands.useAccessGroups=false")
	}
	if cfg.Session.DmScope != "main" {
		t.Errorf("expected session.dmScope=main, got %s", cfg.Session.DmScope)
	}
	if len(cfg.Session.IdentityLinks) != 2 {
		t.Errorf("expected 2 identityLinks entries, got %d", len(cfg.Session.IdentityLinks))
	}
	if cfg.Commands.AllowFrom["*"][0] != "*" {
		t.Fatalf("expected wildcard commands.allowFrom entry in vulnerable fixture")
	}
	telegramWildcard := cfg.Channels["telegram"].Groups["*"]
	if telegramWildcard.RequireMention == nil || *telegramWildcard.RequireMention {
		t.Fatal("expected telegram wildcard group requireMention=false")
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
	if cfg.Commands.UseAccessGroups == nil || !*cfg.Commands.UseAccessGroups {
		t.Fatal("expected commands.useAccessGroups=true")
	}
	if cfg.Session.DmScope != "per-channel-peer" {
		t.Errorf("expected session.dmScope=per-channel-peer, got %s", cfg.Session.DmScope)
	}
	if cfg.Commands.AllowFrom["telegram"][0] != "telegram:alice" {
		t.Fatalf("expected explicit telegram commands.allowFrom entry in clean fixture")
	}
	telegramWildcard := cfg.Channels["telegram"].Groups["*"]
	if telegramWildcard.RequireMention == nil || !*telegramWildcard.RequireMention {
		t.Fatal("expected telegram wildcard group requireMention=true")
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
	_ = cfg.Commands.UseAccessGroups
	_ = cfg.Commands.AllowFrom
	_ = cfg.Session.IdentityLinks
	_ = cfg.Channels["example"].RequireMention
	_ = cfg.Channels["example"].Groups
}
