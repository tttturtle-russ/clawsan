package ioc

import (
	"regexp"
	"strings"
)

func MaliciousDomains() map[string]struct{} {
	return parseLines(maliciousDomains)
}

func C2IPs() map[string]struct{} {
	return parseLines(c2IPs)
}

func MaliciousHashes() map[string]struct{} {
	return parseLines(maliciousHashes)
}

func MaliciousSkillPatterns() []*regexp.Regexp {
	var patterns []*regexp.Regexp
	for _, line := range strings.Split(maliciousSkillPatterns, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		re, err := regexp.Compile(line)
		if err != nil {
			continue
		}
		patterns = append(patterns, re)
	}
	return patterns
}

func parseLines(data string) map[string]struct{} {
	set := make(map[string]struct{})
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		set[line] = struct{}{}
	}
	return set
}
