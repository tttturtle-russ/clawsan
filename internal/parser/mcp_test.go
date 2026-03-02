package parser

import (
	"testing"
)

func TestParseMCP_ExtractsTools(t *testing.T) {
	tools, err := ParseMCPTools("../../testdata/vulnerable-config")
	if err != nil {
		t.Fatalf("ParseMCPTools failed: %v", err)
	}
	if len(tools) == 0 {
		t.Fatal("expected tools to be extracted, got 0")
	}
	found := false
	for _, tool := range tools {
		if tool.Name == "shell_execute" {
			found = true
			if tool.Description == "" {
				t.Error("expected non-empty description for shell_execute")
			}
		}
	}
	if !found {
		t.Error("expected to find shell_execute tool")
	}
}

func TestParseMCP_MissingFile(t *testing.T) {
	tools, err := ParseMCPTools("/nonexistent/path")
	if err != nil {
		t.Fatalf("expected no error for missing TOOLS.md, got: %v", err)
	}
	if len(tools) != 0 {
		t.Errorf("expected 0 tools for missing file, got %d", len(tools))
	}
}

func TestExtractToolsFromMarkdown(t *testing.T) {
	content := `# Available Tools

## shell_execute
Run arbitrary shell commands.
Parameters: command (string)

## file_reader
Read files from the filesystem.
`
	tools := extractToolsFromMarkdown(content, "test")
	if len(tools) != 2 {
		t.Errorf("expected 2 tools, got %d", len(tools))
	}
	if tools[0].Name != "shell_execute" {
		t.Errorf("expected first tool name=shell_execute, got %s", tools[0].Name)
	}
	if tools[1].Name != "file_reader" {
		t.Errorf("expected second tool name=file_reader, got %s", tools[1].Name)
	}
}
