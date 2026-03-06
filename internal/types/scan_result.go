package types

import "time"

// Grade letter thresholds
const (
	GradeA = "A"
	GradeB = "B"
	GradeC = "C"
	GradeD = "D"
	GradeF = "F"
)

// ScanResult holds aggregated scan output
type ScanResult struct {
	Findings    []Finding `json:"findings"`
	Score       int       `json:"score"`
	Grade       string    `json:"grade"`
	TotalChecks int       `json:"total_checks"`
	Summary     string    `json:"summary"`
	Warnings    []string  `json:"warnings,omitempty"`

	// Scan metadata
	ScannedPath string    `json:"scanned_path"`
	ScannedAt   time.Time `json:"scanned_at"`
	Version     string    `json:"version,omitempty"`
	DurationMs  int64     `json:"duration_ms"`

	// Severity breakdown
	Critical int `json:"critical_count"`
	High     int `json:"high_count"`
	Medium   int `json:"medium_count"`
	Low      int `json:"low_count"`
}

// ScoreToGrade converts a numeric score to a letter grade.
func ScoreToGrade(score int) string {
	switch {
	case score >= 90:
		return GradeA
	case score >= 75:
		return GradeB
	case score >= 60:
		return GradeC
	case score >= 40:
		return GradeD
	default:
		return GradeF
	}
}
