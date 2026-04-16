package detectors

import (
	"testing"

	"github.com/tttturtle-russ/clawsan/internal/types"
)

func TestAccessControl_AC001_DmPolicyOpen(t *testing.T) {
	d := NewAccessControlDetector()
	cfg := &types.OpenClawConfig{
		Channels: map[string]types.ChannelConfig{
			"my-channel": {DmPolicy: "open"},
		},
	}
	findings := d.checkAC001ChannelDmPolicyOpen(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for dmPolicy=open, got %d", len(findings))
	}
	if findings[0].ID != "AC-001" {
		t.Errorf("expected AC-001, got %s", findings[0].ID)
	}
	if findings[0].Severity != types.SeverityHigh {
		t.Errorf("expected HIGH, got %s", findings[0].Severity)
	}
}

func TestAccessControl_AC001_DmPolicyAllowlist_NoFinding(t *testing.T) {
	d := NewAccessControlDetector()
	cfg := &types.OpenClawConfig{
		Channels: map[string]types.ChannelConfig{
			"my-channel": {DmPolicy: "allowlist"},
		},
	}
	findings := d.checkAC001ChannelDmPolicyOpen(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for dmPolicy=allowlist, got %d", len(findings))
	}
}

func TestAccessControl_AC002_GroupPolicyOpen(t *testing.T) {
	d := NewAccessControlDetector()
	cfg := &types.OpenClawConfig{
		Channels: map[string]types.ChannelConfig{
			"grp": {GroupPolicy: "open"},
		},
	}
	findings := d.checkAC002ChannelGroupPolicyOpen(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for groupPolicy=open, got %d", len(findings))
	}
	if findings[0].ID != "AC-002" {
		t.Errorf("expected AC-002, got %s", findings[0].ID)
	}
}

func TestAccessControl_AC003_WildcardAllowFrom(t *testing.T) {
	d := NewAccessControlDetector()
	cfg := &types.OpenClawConfig{
		Channels: map[string]types.ChannelConfig{
			"open-channel": {AllowFrom: []string{"user1", "*"}},
		},
	}
	findings := d.checkAC003ChannelWildcardAllowlist(cfg)
	if len(findings) == 0 {
		t.Fatal("expected AC-003 for wildcard in allowFrom")
	}
	if findings[0].ID != "AC-003" {
		t.Errorf("expected AC-003, got %s", findings[0].ID)
	}
}

func TestAccessControl_AC003B_WildcardAllowList(t *testing.T) {
	d := NewAccessControlDetector()
	cfg := &types.OpenClawConfig{
		Channels: map[string]types.ChannelConfig{
			"open-channel": {AllowList: []string{"*"}},
		},
	}
	findings := d.checkAC003ChannelWildcardAllowlist(cfg)
	if len(findings) == 0 {
		t.Fatal("expected AC-003B for wildcard in allowlist")
	}
	if findings[0].ID != "AC-003B" {
		t.Errorf("expected AC-003B, got %s", findings[0].ID)
	}
}

func TestAccessControl_AC004_SandboxOff(t *testing.T) {
	for _, mode := range []string{"off", "none", "permissive"} {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			d := NewAccessControlDetector()
			cfg := &types.OpenClawConfig{
				Sandbox: types.SandboxConfig{Mode: mode},
			}
			findings := d.checkAC004SandboxDisabled(cfg)
			if len(findings) == 0 {
				t.Fatalf("mode=%q: expected AC-004, got none", mode)
			}
			if findings[0].ID != "AC-004" {
				t.Errorf("expected AC-004, got %s", findings[0].ID)
			}
		})
	}
}

func TestAccessControl_AC004_SandboxStrict_NoFinding(t *testing.T) {
	d := NewAccessControlDetector()
	cfg := &types.OpenClawConfig{
		Sandbox: types.SandboxConfig{Mode: "strict"},
	}
	findings := d.checkAC004SandboxDisabled(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for sandbox=strict, got %d", len(findings))
	}
}

func TestAccessControl_AC005_AcpAutoApproveAll(t *testing.T) {
	d := NewAccessControlDetector()
	cfg := &types.OpenClawConfig{
		Acp: types.AcpConfig{AutoApprove: "all"},
	}
	findings := d.checkAC005AcpAutoApproveAll(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 AC-005 finding, got %d", len(findings))
	}
	if findings[0].ID != "AC-005" {
		t.Errorf("expected AC-005, got %s", findings[0].ID)
	}
	if findings[0].Severity != types.SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", findings[0].Severity)
	}
}

func TestAccessControl_AC005_AcpAutoApproveNone_NoFinding(t *testing.T) {
	d := NewAccessControlDetector()
	cfg := &types.OpenClawConfig{
		Acp: types.AcpConfig{AutoApprove: "none"},
	}
	findings := d.checkAC005AcpAutoApproveAll(cfg)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for autoApprove=none, got %d", len(findings))
	}
}

func TestAccessControl_AC006_SessionDmScopeGlobal_MultiChannel(t *testing.T) {
	d := NewAccessControlDetector()
	cfg := &types.OpenClawConfig{
		Channels: map[string]types.ChannelConfig{
			"chan-a": {},
			"chan-b": {},
		},
		Session: types.SessionConfig{DmScope: "main"},
	}
	f := d.checkAC006SessionDmScopeGlobal(cfg)
	if f == nil {
		t.Fatal("expected AC-006 for main dmScope with 2+ channels")
	}
	if f.ID != "AC-006" {
		t.Errorf("expected AC-006, got %s", f.ID)
	}
}

func TestAccessControl_AC006_SingleChannel_NoFinding(t *testing.T) {
	d := NewAccessControlDetector()
	cfg := &types.OpenClawConfig{
		Channels: map[string]types.ChannelConfig{
			"only-channel": {},
		},
		Session: types.SessionConfig{DmScope: "main"},
	}
	f := d.checkAC006SessionDmScopeGlobal(cfg)
	if f != nil {
		t.Errorf("expected nil for single channel, got %s", f.ID)
	}
}

func TestAccessControl_AC007_CommandsUseAccessGroupsFalse(t *testing.T) {
	d := NewAccessControlDetector()
	useAccessGroups := false
	cfg := &types.OpenClawConfig{
		Commands: types.CommandsConfig{UseAccessGroups: &useAccessGroups},
	}
	f := d.checkAC007CommandsUseAccessGroups(cfg)
	if f == nil {
		t.Fatal("expected AC-007 when commands.useAccessGroups=false")
	}
	if f.ID != "AC-007" {
		t.Errorf("expected AC-007, got %s", f.ID)
	}
}

func TestAccessControl_AC007_AllowFromOverridesUseAccessGroups(t *testing.T) {
	d := NewAccessControlDetector()
	useAccessGroups := false
	cfg := &types.OpenClawConfig{
		Commands: types.CommandsConfig{
			UseAccessGroups: &useAccessGroups,
			AllowFrom: map[string][]string{
				"telegram:alice": {"/exec"},
			},
		},
	}
	f := d.checkAC007CommandsUseAccessGroups(cfg)
	if f != nil {
		t.Errorf("expected nil when commands.allowFrom is configured, got %s", f.ID)
	}
}

func TestAccessControl_AC008_InvalidIdentityLinksFormat(t *testing.T) {
	d := NewAccessControlDetector()
	cfg := &types.OpenClawConfig{
		Session: types.SessionConfig{
			IdentityLinks: map[string][]string{
				"wechat:alice": {"telegram:alice", "alice"},
			},
		},
	}
	findings := d.checkAC008IdentityLinksFormat(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 AC-008 finding, got %d", len(findings))
	}
	if findings[0].ID != "AC-008" {
		t.Errorf("expected AC-008, got %s", findings[0].ID)
	}
}

func TestAccessControl_AC009_OverlappingIdentityLinks(t *testing.T) {
	d := NewAccessControlDetector()
	cfg := &types.OpenClawConfig{
		Session: types.SessionConfig{
			IdentityLinks: map[string][]string{
				"wechat:alice": {"telegram:alice", "discord:shared"},
				"wechat:bob":   {"discord:shared"},
			},
		},
	}
	findings := d.checkAC009IdentityLinksOverlap(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 AC-009 finding, got %d", len(findings))
	}
	if findings[0].ID != "AC-009" {
		t.Errorf("expected AC-009, got %s", findings[0].ID)
	}
}

func TestAccessControl_AC010_CommandsWildcardAllowFrom(t *testing.T) {
	d := NewAccessControlDetector()
	cfg := &types.OpenClawConfig{
		Commands: types.CommandsConfig{
			AllowFrom: map[string][]string{
				"*": {"*"},
			},
		},
	}
	findings := d.checkAC010CommandsWildcardAllowFrom(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 AC-010 finding, got %d", len(findings))
	}
	if findings[0].ID != "AC-010" {
		t.Errorf("expected AC-010, got %s", findings[0].ID)
	}
}

func TestAccessControl_AC010_ExplicitSenders_NoFinding(t *testing.T) {
	d := NewAccessControlDetector()
	cfg := &types.OpenClawConfig{
		Commands: types.CommandsConfig{
			AllowFrom: map[string][]string{
				"telegram": {"telegram:alice"},
			},
		},
	}
	findings := d.checkAC010CommandsWildcardAllowFrom(cfg)
	if len(findings) != 0 {
		t.Fatalf("expected 0 AC-010 findings, got %d", len(findings))
	}
}

func TestAccessControl_AC011_ChannelRequireMentionFalseWithOpenGroups(t *testing.T) {
	d := NewAccessControlDetector()
	requireMention := false
	cfg := &types.OpenClawConfig{
		Channels: map[string]types.ChannelConfig{
			"telegram": {
				GroupPolicy:    "open",
				RequireMention: &requireMention,
			},
		},
	}
	findings := d.checkAC011OpenGroupsWithoutMentionGate(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 AC-011 finding, got %d", len(findings))
	}
	if findings[0].ID != "AC-011" {
		t.Errorf("expected AC-011, got %s", findings[0].ID)
	}
}

func TestAccessControl_AC011_GroupWildcardRequireMentionFalse(t *testing.T) {
	d := NewAccessControlDetector()
	requireMention := false
	cfg := &types.OpenClawConfig{
		Channels: map[string]types.ChannelConfig{
			"telegram": {
				GroupPolicy: "open",
				Groups: map[string]types.ChannelGroupRule{
					"*": {RequireMention: &requireMention},
				},
			},
		},
	}
	findings := d.checkAC011OpenGroupsWithoutMentionGate(cfg)
	if len(findings) != 1 {
		t.Fatalf("expected 1 AC-011 finding, got %d", len(findings))
	}
	if findings[0].ID != "AC-011" {
		t.Errorf("expected AC-011, got %s", findings[0].ID)
	}
}

func TestAccessControl_AC011_RequireMentionTrue_NoFinding(t *testing.T) {
	d := NewAccessControlDetector()
	requireMention := true
	cfg := &types.OpenClawConfig{
		Channels: map[string]types.ChannelConfig{
			"telegram": {
				GroupPolicy: "open",
				Groups: map[string]types.ChannelGroupRule{
					"*": {RequireMention: &requireMention},
				},
			},
		},
	}
	findings := d.checkAC011OpenGroupsWithoutMentionGate(cfg)
	if len(findings) != 0 {
		t.Fatalf("expected 0 AC-011 findings, got %d", len(findings))
	}
}

func TestAccessControl_NilConfig_NoFindings(t *testing.T) {
	d := NewAccessControlDetector()
	findings := d.Detect(nil)
	if findings != nil {
		t.Errorf("expected nil for nil config, got %v", findings)
	}
}
