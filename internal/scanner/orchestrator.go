package scanner

import (
	"time"

	"github.com/tttturtle-russ/clawsan/internal/detectors"
	"github.com/tttturtle-russ/clawsan/internal/parser"
	"github.com/tttturtle-russ/clawsan/internal/scoring"
	"github.com/tttturtle-russ/clawsan/internal/types"
)

// Version is set at build time via -ldflags "-X github.com/tttturtle-russ/clawsan/internal/scanner.Version=v1.2.3"
var Version = "dev"

func Scan(path string) (*types.ScanResult, error) {
	start := time.Now()

	cfg, err := parser.ParseConfig(path)
	if err != nil {
		return nil, err
	}

	var warnings []string

	workspace, err := parser.ParseWorkspaceFiles(path)
	if err != nil {
		warnings = append(warnings, "could not parse workspace files: "+err.Error())
		workspace = nil
	}

	tools, err := parser.ParseMCPTools(path)
	if err != nil {
		warnings = append(warnings, "could not parse MCP tools: "+err.Error())
		tools = []parser.MCPTool{}
	}

	slugs := make([]string, len(cfg.Skills))
	for i, s := range cfg.Skills {
		slugs[i] = s.Name
	}
	installedSkills, err := parser.ParseSkillFiles(path, slugs)
	if err != nil {
		warnings = append(warnings, "could not parse skill files: "+err.Error())
		installedSkills = nil
	}

	var allFindings []types.Finding

	supplyChain := detectors.NewSupplyChainDetector()
	allFindings = append(allFindings, supplyChain.Detect(cfg)...)
	if len(installedSkills) > 0 {
		allFindings = append(allFindings, supplyChain.CheckSkillMetadata(cfg, installedSkills)...)
	}

	configuration := detectors.NewConfigurationDetector()
	allFindings = append(allFindings, configuration.Detect(cfg)...)

	discovery := detectors.NewDiscoveryDetector()
	allFindings = append(allFindings, discovery.Detect(workspace, tools)...)

	runtime := detectors.NewRuntimeDetector()
	allFindings = append(allFindings, runtime.Detect(workspace, tools, cfg)...)

	if len(installedSkills) > 0 {
		skillContent := detectors.NewSkillContentDetector()
		allFindings = append(allFindings, skillContent.Detect(installedSkills)...)

		skillIdentity := detectors.NewSkillIdentityDetector()
		allFindings = append(allFindings, skillIdentity.Detect(slugs)...)

		composite := detectors.NewSkillCompositeDetector()
		allFindings = append(allFindings, composite.Detect(cfg.Skills, installedSkills)...)
	} else {
		skillIdentity := detectors.NewSkillIdentityDetector()
		allFindings = append(allFindings, skillIdentity.Detect(slugs)...)
	}

	score, grade, critical, high, medium, low := scoring.Calculate(allFindings)

	return &types.ScanResult{
		Findings:    allFindings,
		Score:       score,
		Grade:       grade,
		TotalChecks: 33,
		Warnings:    warnings,
		ScannedPath: path,
		ScannedAt:   start,
		Version:     Version,
		DurationMs:  time.Since(start).Milliseconds(),
		Critical:    critical,
		High:        high,
		Medium:      medium,
		Low:         low,
	}, nil
}
