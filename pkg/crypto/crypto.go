// Package crypto provides cryptographic analysis and weak cipher detection.
package crypto

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"regexp"
)

// WeakAlgorithm represents a weak cryptographic algorithm.
type WeakAlgorithm struct {
	Name        string
	Description string
	CVSSScore   float64
	ReplacedBy  string
	Examples    []string
}

// KeyStrength represents key strength analysis.
type KeyStrength struct {
	KeyType   string
	KeySize   int
	Strength  string // weak, moderate, strong
	Recommendation string
}

// ConfigIssue represents a cryptographic configuration issue.
type ConfigIssue struct {
	Type        string
	Description string
	Severity    string // low, medium, high, critical
	Recommendation string
	File        string
	Line        int
}

// AuditResult represents the complete cryptographic audit.
type AuditResult struct {
	Target          string
	ScanTime        string
	WeakAlgorithms  []WeakAlgorithm
	KeyStrengths    []KeyStrength
	ConfigIssues    []ConfigIssue
	HashAnalysis    []HashAnalysis
	OverallScore    float64
	Compliance      map[string]bool
}

// HashAnalysis represents hash function analysis.
type HashAnalysis struct {
	Algorithm string
	Strength  string // weak, moderate, strong
	Recommended bool
}

// Scanner analyzes cryptographic configurations and code.
type Scanner struct {
	weakAlgorithms map[string]WeakAlgorithm
	hashPatterns   []*regexp.Regexp
	deprecatedHashes []string
}

// NewScanner creates a new cryptographic scanner.
func NewScanner() *Scanner {
	return &Scanner{
		weakAlgorithms: map[string]WeakAlgorithm{
			"MD5": {
				Name:        "MD5",
				Description: "MD5 hash function is cryptographically broken",
				CVSSScore:   7.5,
				ReplacedBy:  "SHA-256 or SHA-3",
				Examples:    []string{"md5", "MD5"},
			},
			"SHA1": {
				Name:        "SHA-1",
				Description: "SHA-1 has known collision vulnerabilities",
				CVSSScore:   6.5,
				ReplacedBy:  "SHA-256 or SHA-3",
				Examples:    []string{"sha1", "SHA1", "SHA-1"},
			},
			"DES": {
				Name:        "DES",
				Description: "DES uses 56-bit key, easily brute-forced",
				CVSSScore:   8.0,
				ReplacedBy:  "AES-256",
				Examples:    []string{"des", "DES"},
			},
			"3DES": {
				Name:        "3DES",
				Description: "Triple DES is deprecated, slow and weaker than AES",
				CVSSScore:   5.5,
				ReplacedBy:  "AES-256",
				Examples:    []string{"3des", "3DES", "tripledes"},
			},
			"RC4": {
				Name:        "RC4",
				Description: "RC4 has multiple proven vulnerabilities",
				CVSSScore:   7.0,
				ReplacedBy:  "AES-GCM",
				Examples:    []string{"rc4", "RC4"},
			},
			"MD4": {
				Name:        "MD4",
				Description: "MD4 is severely broken, not suitable for any use",
				CVSSScore:   9.0,
				ReplacedBy:  "SHA-256",
				Examples:    []string{"md4", "MD4"},
			},
		},
		deprecatedHashes: []string{"md5", "sha1", "md4"},
		hashPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)\b(md5)\b`),
			regexp.MustCompile(`(?i)\b(sha1|sha-1)\b`),
			regexp.MustCompile(`(?i)\b(md4)\b`),
			regexp.MustCompile(`(?i)\b(des|3des)\b`),
			regexp.MustCompile(`(?i)\b(rc4|arcfour)\b`),
			regexp.MustCompile(`(?i)\b(weak_crypto|weakcrypto)\b`),
			regexp.MustCompile(`(?i)hash\s*[=:]\s*['"]?(md5|sha1)\b`),
		},
	}
}

// AnalyzeAlgorithm analyzes a cryptographic algorithm.
func (s *Scanner) AnalyzeAlgorithm(algorithm string) *WeakAlgorithm {
	algLower := regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(algorithm, "")
	algLower = regexp.MustCompile(`-|\s`).ReplaceAllString(algLower, "")

	for name, weak := range s.weakAlgorithms {
		weakName := regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(name, "")
		if algLower == weakName || algLower == name {
			return &weak
		}
	}
	return nil
}

// AnalyzeKeyStrength analyzes key strength.
func AnalyzeKeyStrength(keyType string, keySize int) KeyStrength {
	keyType = regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(keyType, "")
	keyTypeLower := regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(keyType, "")

	var strength string
	var recommendation string

	switch keyTypeLower {
	case "aes", "aes-128", "aes128":
		if keySize >= 256 {
			strength = "strong"
			recommendation = "Excellent key strength"
		} else if keySize >= 128 {
			strength = "moderate"
			recommendation = "Consider upgrading to AES-256"
		} else {
			strength = "weak"
			recommendation = "Increase key size to at least 128 bits"
		}
	case "aes-256", "aes256":
		strength = "strong"
		recommendation = "Excellent key strength"
	case "rsa":
		if keySize >= 4096 {
			strength = "strong"
			recommendation = "Excellent key strength"
		} else if keySize >= 2048 {
			strength = "moderate"
			recommendation = "Consider upgrading to 4096 bits"
		} else {
			strength = "weak"
			recommendation = "Increase key size to at least 2048 bits"
		}
	case "ecc", "ecdsa":
		if keySize >= 384 {
			strength = "strong"
			recommendation = "Excellent key strength"
		} else if keySize >= 256 {
			strength = "moderate"
			recommendation = "Consider upgrading to P-384"
		} else {
			strength = "weak"
			recommendation = "Increase key size to at least 256 bits"
		}
	default:
		strength = "unknown"
		recommendation = "Unknown key type, verify security requirements"
	}

	return KeyStrength{
		KeyType:      keyType,
		KeySize:      keySize,
		Strength:     strength,
		Recommendation: recommendation,
	}
}

// ScanContent scans content for weak cryptographic patterns.
func (s *Scanner) ScanContent(content string) []ConfigIssue {
	var issues []ConfigIssue

	for _, pattern := range s.hashPatterns {
		matches := pattern.FindAllStringIndex(content, -1)
		for _, match := range matches {
			matched := content[match[0]:match[1]]
			
			weak := s.AnalyzeAlgorithm(matched)
			if weak != nil {
				issues = append(issues, ConfigIssue{
					Type:        "Weak Cryptographic Algorithm",
					Description: weak.Description,
					Severity:    getSeverity(weak.CVSSScore),
					Recommendation: fmt.Sprintf("Replace with %s", weak.ReplacedBy),
					File:        "detected in content",
					Line:        match[0],
				})
			}
		}
	}

	return issues
}

// AnalyzeHash analyzes a hash value.
func AnalyzeHash(hashValue string) HashAnalysis {
	hashValue = regexp.MustCompile(`[^a-f0-9]+`).ReplaceAllString(hashValue, "")
	hashValue = regexp.ToLower(hashValue)

	analysis := HashAnalysis{
		Algorithm: "unknown",
		Strength:  "unknown",
		Recommended: false,
	}

	// MD5 - 32 hex chars
	if len(hashValue) == 32 && isHex(hashValue) {
		analysis.Algorithm = "MD5"
		analysis.Strength = "weak"
		analysis.Recommended = false
		return analysis
	}

	// SHA1 - 40 hex chars
	if len(hashValue) == 40 && isHex(hashValue) {
		analysis.Algorithm = "SHA-1"
		analysis.Strength = "weak"
		analysis.Recommended = false
		return analysis
	}

	// SHA256 - 64 hex chars
	if len(hashValue) == 64 && isHex(hashValue) {
		analysis.Algorithm = "SHA-256"
		analysis.Strength = "strong"
		analysis.Recommended = true
		return analysis
	}

	// SHA384 - 96 hex chars
	if len(hashValue) == 96 && isHex(hashValue) {
		analysis.Algorithm = "SHA-384"
		analysis.Strength = "strong"
		analysis.Recommended = true
		return analysis
	}

	// SHA512 - 128 hex chars
	if len(hashValue) == 128 && isHex(hashValue) {
		analysis.Algorithm = "SHA-512"
		analysis.Strength = "strong"
		analysis.Recommended = true
		return analysis
	}

	return analysis
}

// GetWeakAlgorithms returns all weak algorithms.
func (s *Scanner) GetWeakAlgorithms() []WeakAlgorithm {
	var weak []WeakAlgorithm
	for _, alg := range s.weakAlgorithms {
		weak = append(weak, alg)
	}
	return weak
}

// CalculateScore calculates overall cryptographic score.
func CalculateScore(issues []ConfigIssue) float64 {
	if len(issues) == 0 {
		return 100.0
	}

	score := 100.0
	for _, issue := range issues {
		switch issue.Severity {
		case "critical":
			score -= 25
		case "high":
			score -= 15
		case "medium":
			score -= 8
		case "low":
			score -= 3
		}
	}

	if score < 0 {
		score = 0
	}
	return score
}

// GetSeverity converts CVSS score to severity string.
func getSeverity(cvss float64) string {
	if cvss >= 9.0 {
		return "critical"
	} else if cvss >= 7.0 {
		return "high"
	} else if cvss >= 4.0 {
		return "medium"
	}
	return "low"
}

// isHex checks if string is valid hexadecimal.
func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

// HashString computes hash of string.
func HashString(input string, algo string) (string, error) {
	var h hash.Hash

	switch algo {
	case "md5":
		h = md5.New()
	case "sha1":
		h = sha1.New()
	case "sha256":
		h = sha256.New()
	case "sha512":
		h = sha512.New()
	default:
		return "", fmt.Errorf("unsupported hash algorithm: %s", algo)
	}

	h.Write([]byte(input))
	return hex.EncodeToString(h.Sum(nil)), nil
}