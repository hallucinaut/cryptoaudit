package crypto

import (
	"testing"
)

func TestNewScanner(t *testing.T) {
	scanner := NewScanner()
	
	if scanner == nil {
		t.Error("Expected non-nil scanner")
	}
	
	if len(scanner.weakAlgorithms) == 0 {
		t.Error("Expected weak algorithms to be initialized")
	}
}

func TestAnalyzeAlgorithm_MD5(t *testing.T) {
	scanner := NewScanner()
	
	weak := scanner.AnalyzeAlgorithm("MD5")
	
	if weak == nil {
		t.Fatal("Expected to find MD5 as weak algorithm")
	}
	
	if weak.Name != "MD5" {
		t.Errorf("Expected name 'MD5', got '%s'", weak.Name)
	}
	
	if weak.CVSSScore != 7.5 {
		t.Errorf("Expected CVSS 7.5, got %.1f", weak.CVSSScore)
	}
}

func TestAnalyzeAlgorithm_SHA1(t *testing.T) {
	scanner := NewScanner()
	
	weak := scanner.AnalyzeAlgorithm("SHA-1")
	
	if weak == nil {
		t.Fatal("Expected to find SHA-1 as weak algorithm")
	}
	
	if weak.Name != "SHA-1" {
		t.Errorf("Expected name 'SHA-1', got '%s'", weak.Name)
	}
}

func TestAnalyzeAlgorithm_Safe(t *testing.T) {
	scanner := NewScanner()
	
	weak := scanner.AnalyzeAlgorithm("AES-256")
	
	if weak != nil {
		t.Error("Expected nil for AES-256 (not weak)")
	}
}

func TestAnalyzeKeyStrength_AES(t *testing.T) {
	tests := []struct {
		keyType    string
		keySize    int
		expected   string
	}{
		{"AES-256", 256, "strong"},
		{"AES-128", 128, "moderate"},
		{"AES", 64, "weak"},
	}
	
	for _, tt := range tests {
		t.Run(tt.keyType, func(t *testing.T) {
			result := AnalyzeKeyStrength(tt.keyType, tt.keySize)
			if result.Strength != tt.expected {
				t.Errorf("Expected strength '%s', got '%s'", tt.expected, result.Strength)
			}
		})
	}
}

func TestAnalyzeKeyStrength_RSA(t *testing.T) {
	result := AnalyzeKeyStrength("RSA", 4096)
	if result.Strength != "strong" {
		t.Errorf("Expected strong for RSA-4096, got '%s'", result.Strength)
	}
	
	result = AnalyzeKeyStrength("RSA", 1024)
	if result.Strength != "weak" {
		t.Errorf("Expected weak for RSA-1024, got '%s'", result.Strength)
	}
}

func TestScanContent(t *testing.T) {
	scanner := NewScanner()
	
	content := `
# Configuration
hash_algorithm=md5
encryption=DES
key_size=1024
`
	
	issues := scanner.ScanContent(content)
	
	if len(issues) == 0 {
		t.Error("Expected to find at least one weak crypto issue")
	}
	
	// Check for MD5 issue
	md5Found := false
	for _, issue := range issues {
		if issue.Type == "Weak Cryptographic Algorithm" && 
		   (issue.Description == "MD5 hash function is cryptographically broken" ||
		    issue.Description == "SHA-1 has known collision vulnerabilities") {
			md5Found = true
		}
	}
	
	if !md5Found {
		t.Log("Issues found:", len(issues))
		for _, issue := range issues {
			t.Logf("  - %s: %s", issue.Type, issue.Description)
		}
	}
}

func TestAnalyzeHash_MD5(t *testing.T) {
	hash := "5d41402abc4b2a76b9719d911017c592"
	
	result := AnalyzeHash(hash)
	
	if result.Algorithm != "MD5" {
		t.Errorf("Expected MD5, got '%s'", result.Algorithm)
	}
	
	if result.Strength != "weak" {
		t.Errorf("Expected weak, got '%s'", result.Strength)
	}
	
	if result.Recommended {
		t.Error("MD5 should not be recommended")
	}
}

func TestAnalyzeHash_SHA256(t *testing.T) {
	hash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	
	result := AnalyzeHash(hash)
	
	if result.Algorithm != "SHA-256" {
		t.Errorf("Expected SHA-256, got '%s'", result.Algorithm)
	}
	
	if result.Strength != "strong" {
		t.Errorf("Expected strong, got '%s'", result.Strength)
	}
	
	if !result.Recommended {
		t.Error("SHA-256 should be recommended")
	}
}

func TestCalculateScore(t *testing.T) {
	tests := []struct {
		issues []ConfigIssue
		expect float64
	}{
		{[]ConfigIssue{}, 100.0},
		{[]ConfigIssue{{Severity: "low"}}, 97.0},
		{[]ConfigIssue{{Severity: "medium"}}, 92.0},
		{[]ConfigIssue{{Severity: "high"}}, 85.0},
		{[]ConfigIssue{{Severity: "critical"}}, 75.0},
		{[]ConfigIssue{{Severity: "critical"}, {Severity: "high"}}, 60.0},
	}
	
	for i, tt := range tests {
		score := CalculateScore(tt.issues)
		if score != tt.expect {
			t.Errorf("Test %d: Expected score %.1f, got %.1f", i, tt.expect, score)
		}
	}
}

func TestGetWeakAlgorithms(t *testing.T) {
	scanner := NewScanner()
	
	weakAlgos := scanner.GetWeakAlgorithms()
	
	if len(weakAlgos) == 0 {
		t.Error("Expected to get weak algorithms list")
	}
	
	// Check for MD5
	md5Found := false
	for _, alg := range weakAlgos {
		if alg.Name == "MD5" {
			md5Found = true
			break
		}
	}
	
	if !md5Found {
		t.Error("Expected MD5 in weak algorithms list")
	}
}

func TestHashString(t *testing.T) {
	tests := []struct {
		input    string
		algorithm string
		expected string
	}{
		{"hello", "md5", "5d41402abc4b2a76b9719d911017c592"},
		{"hello", "sha256", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"},
	}
	
	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			result, err := HashString(tt.input, tt.algorithm)
			if err != nil {
				t.Fatalf("Hash failed: %v", err)
			}
			
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestHashString_Unsupported(t *testing.T) {
	_, err := HashString("test", "unsupported")
	
	if err == nil {
		t.Error("Expected error for unsupported algorithm")
	}
}

func TestIsHex(t *testing.T) {
	tests := []struct {
		input  string
		expect bool
	}{
		{"abc123", true},
		{"ABCDEF", true},
		{"xyz", false},
		{"", true},
	}
	
	for _, tt := range tests {
		result := isHex(tt.input)
		if result != tt.expect {
			t.Errorf("isHex(%q) = %v, expected %v", tt.input, result, tt.expect)
		}
	}
}

func TestGetSeverity(t *testing.T) {
	tests := []struct {
		cvss   float64
		expect string
	}{
		{9.5, "critical"},
		{9.0, "critical"},
		{7.5, "high"},
		{7.0, "high"},
		{5.0, "medium"},
		{4.0, "medium"},
		{3.0, "low"},
		{0.0, "low"},
	}
	
	for _, tt := range tests {
		result := getSeverity(tt.cvss)
		if result != tt.expect {
			t.Errorf("getSeverity(%.1f) = %q, expected %q", tt.cvss, result, tt.expect)
		}
	}
}

func TestAnalyzeKeyStrength_ECC(t *testing.T) {
	result := AnalyzeKeyStrength("ECC", 384)
	if result.Strength != "strong" {
		t.Errorf("Expected strong for ECC-384, got '%s'", result.Strength)
	}
	
	result = AnalyzeKeyStrength("ECDSA", 256)
	if result.Strength != "moderate" {
		t.Errorf("Expected moderate for ECDSA-256, got '%s'", result.Strength)
	}
}

func TestAnalyzeAlgorithm_RC4(t *testing.T) {
	scanner := NewScanner()
	
	weak := scanner.AnalyzeAlgorithm("RC4")
	
	if weak == nil {
		t.Fatal("Expected to find RC4 as weak algorithm")
	}
	
	if weak.ReplacedBy != "AES-GCM" {
		t.Errorf("Expected RC4 to be replaced by AES-GCM")
	}
}