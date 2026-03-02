package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WorkspaceData holds the contents of OpenClaw workspace files
type WorkspaceData struct {
	AgentsMD      string // contents of AGENTS.md
	ToolsMD       string // contents of TOOLS.md
	HeartbeatMD   string // contents of HEARTBEAT.md
	AgentsPath    string // absolute path to AGENTS.md
	ToolsPath     string // absolute path to TOOLS.md
	HeartbeatPath string // absolute path to HEARTBEAT.md
}

// ParseWorkspaceFiles reads workspace markdown files from the given directory.
// The workspacePath should be the OpenClaw installation root (e.g. ~/.openclaw/).
// Workspace files are expected at workspacePath/workspace/
// Missing files are not errors — they result in empty strings.
func ParseWorkspaceFiles(installPath string) (*WorkspaceData, error) {
	if strings.HasPrefix(installPath, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("could not determine home directory: %w", err)
		}
		installPath = filepath.Join(home, installPath[2:])
	}

	workspacePath := filepath.Join(installPath, "workspace")

	if _, err := os.Stat(workspacePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("workspace directory not found: %s", workspacePath)
	}

	data := &WorkspaceData{
		AgentsPath:    filepath.Join(workspacePath, "AGENTS.md"),
		ToolsPath:     filepath.Join(workspacePath, "TOOLS.md"),
		HeartbeatPath: filepath.Join(workspacePath, "HEARTBEAT.md"),
	}

	data.AgentsMD = readFileOrEmpty(data.AgentsPath)
	data.ToolsMD = readFileOrEmpty(data.ToolsPath)
	data.HeartbeatMD = readFileOrEmpty(data.HeartbeatPath)

	return data, nil
}

// readFileOrEmpty reads a file and returns its content, or empty string if it doesn't exist.
func readFileOrEmpty(path string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(content)
}
