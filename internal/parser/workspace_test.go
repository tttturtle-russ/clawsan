package parser

import (
	"strings"
	"testing"
)

func TestParseWorkspace_Vulnerable(t *testing.T) {
	data, err := ParseWorkspaceFiles("../../testdata/vulnerable-config")
	if err != nil {
		t.Fatalf("ParseWorkspaceFiles failed: %v", err)
	}
	if data.AgentsMD == "" {
		t.Error("expected non-empty AGENTS.md")
	}
	if !strings.Contains(data.AgentsMD, "evil.example.com") {
		t.Error("expected poisoning pattern in AGENTS.md")
	}
	if data.ToolsMD == "" {
		t.Error("expected non-empty TOOLS.md")
	}
	if !strings.Contains(data.ToolsMD, "shell_execute") {
		t.Error("expected shell_execute in TOOLS.md")
	}
	if data.HeartbeatMD == "" {
		t.Error("expected non-empty HEARTBEAT.md")
	}
}

func TestParseWorkspace_MissingDir(t *testing.T) {
	_, err := ParseWorkspaceFiles("/nonexistent/path")
	if err == nil {
		t.Error("expected error for missing workspace directory")
	}
}
