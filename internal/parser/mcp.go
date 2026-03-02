package parser

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// MCPTool represents an MCP tool definition extracted from workspace
type MCPTool struct {
	Name        string
	Description string
	Source      string // where the tool comes from (file path)
}

// ParseMCPTools extracts MCP tool definitions from TOOLS.md in the workspace.
// Tools are identified by markdown h2 headers (## ToolName) followed by description text.
// Returns empty slice (not error) if no tools found.
func ParseMCPTools(installPath string) ([]MCPTool, error) {
	// Expand ~
	if strings.HasPrefix(installPath, "~/") {
		home, _ := os.UserHomeDir()
		installPath = filepath.Join(home, installPath[2:])
	}

	toolsPath := filepath.Join(installPath, "workspace", "TOOLS.md")
	data, err := os.ReadFile(toolsPath)
	if err != nil {
		// Missing TOOLS.md is not an error — just no tools
		return []MCPTool{}, nil
	}

	return extractToolsFromMarkdown(string(data), toolsPath), nil
}

// extractToolsFromMarkdown parses markdown looking for ## ToolName sections
func extractToolsFromMarkdown(content string, sourcePath string) []MCPTool {
	var tools []MCPTool

	// Match ## heading as tool name
	headerRe := regexp.MustCompile(`(?m)^## (.+)$`)
	matches := headerRe.FindAllStringSubmatchIndex(content, -1)

	for i, match := range matches {
		name := strings.TrimSpace(content[match[2]:match[3]])

		// Extract description: text between this header and next header (or EOF)
		start := match[1]
		var end int
		if i+1 < len(matches) {
			end = matches[i+1][0]
		} else {
			end = len(content)
		}

		description := strings.TrimSpace(content[start:end])
		tools = append(tools, MCPTool{
			Name:        name,
			Description: description,
			Source:      sourcePath,
		})
	}

	return tools
}
