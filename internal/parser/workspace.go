package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type WorkspaceData struct {
	AgentsMD      string
	ToolsMD       string
	HeartbeatMD   string
	SoulMD        string
	MemoryMD      string
	IdentityMD    string
	AgentsPath    string
	ToolsPath     string
	HeartbeatPath string
	SoulPath      string
	MemoryPath    string
	IdentityPath  string
}

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
		SoulPath:      filepath.Join(workspacePath, "SOUL.md"),
		MemoryPath:    filepath.Join(workspacePath, "MEMORY.md"),
		IdentityPath:  filepath.Join(workspacePath, "IDENTITY.md"),
	}

	data.AgentsMD = readFileOrEmpty(data.AgentsPath)
	data.ToolsMD = readFileOrEmpty(data.ToolsPath)
	data.HeartbeatMD = readFileOrEmpty(data.HeartbeatPath)
	data.SoulMD = readFileOrEmpty(data.SoulPath)
	data.MemoryMD = readFileOrEmpty(data.MemoryPath)
	data.IdentityMD = readFileOrEmpty(data.IdentityPath)

	return data, nil
}

func readFileOrEmpty(path string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(content)
}
