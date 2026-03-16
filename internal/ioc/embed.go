package ioc

import _ "embed"

//go:embed malicious-domains.txt
var maliciousDomains string

//go:embed c2-ips.txt
var c2IPs string

//go:embed malicious-hashes.txt
var maliciousHashes string

//go:embed malicious-skill-patterns.txt
var maliciousSkillPatterns string
