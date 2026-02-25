# cryptoaudit - Cryptographic Weakness Scanner

[![Go](https://img.shields.io/badge/Go-1.21-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

**Automated cryptographic weakness scanner for codebases and configurations.**

Identify weak cryptographic algorithms, deprecated hash functions, and insecure configurations in your codebase.

## 🚀 Features

- **Weak Algorithm Detection**: Find MD5, SHA-1, DES, 3DES, RC4, MD4 usage
- **Key Strength Analysis**: Evaluate RSA, ECC, and AES key sizes
- **Hash Function Analysis**: Identify weak hash functions in code
- **Configuration Scanning**: Scan config files for crypto issues
- **Security Scoring**: Calculate overall cryptographic security score
- **Compliance Checks**: Check against industry best practices

## 📦 Installation

### Build from Source

```bash
git clone https://github.com/hallucinaut/cryptoaudit.git
cd cryptoaudit
go build -o cryptoaudit ./cmd/cryptoaudit
sudo mv cryptoaudit /usr/local/bin/
```

### Install via Go

```bash
go install github.com/hallucinaut/cryptoaudit/cmd/cryptoaudit@latest
```

## 🎯 Usage

### Scan Project

```bash
# Scan entire project directory
cryptoaudit scan ./myproject

# Scan specific directory
cryptoaudit scan /path/to/project
```

### Check Configuration

```bash
# Check a single config file
cryptoaudit check config.yaml
cryptoaudit check ssl.conf
```

### Programmatic Usage

```go
package main

import (
    "fmt"
    "github.com/hallucinaut/cryptoaudit/pkg/crypto"
)

func main() {
    scanner := crypto.NewScanner()
    
    // Scan content
    content := `hash=md5; encryption=DES`
    issues := scanner.ScanContent(content)
    
    fmt.Printf("Found %d issues\n", len(issues))
    
    // Analyze key strength
    keyStrength := crypto.AnalyzeKeyStrength("RSA", 2048)
    fmt.Printf("Key strength: %s\n", keyStrength.Strength)
    
    // Calculate security score
    score := crypto.CalculateScore(issues)
    fmt.Printf("Security score: %.0f%%\n", score)
}
```

## 🔍 Supported Weak Algorithms

| Algorithm | CVSS | Replaced By | Status |
|-----------|------|-------------|--------|
| MD4 | 9.0 | SHA-256 | Severely broken |
| MD5 | 7.5 | SHA-256 | Cryptographically broken |
| SHA-1 | 6.5 | SHA-256 | Collision attacks practical |
| DES | 8.0 | AES-256 | 56-bit key easily brute-forced |
| 3DES | 5.5 | AES-256 | Deprecated, slow |
| RC4 | 7.0 | AES-GCM | Multiple proven vulnerabilities |

## 📊 Security Score

| Score | Status | Action Required |
|-------|--------|-----------------|
| 90-100 | Excellent | Continue monitoring |
| 70-89 | Good | Address medium issues |
| 50-69 | Fair | Address high/critical issues |
| <50 | Poor | Immediate action required |

## 🧪 Testing

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific test
go test -v ./pkg/crypto -run TestAnalyzeAlgorithm
```

## 📋 Example Output

```
Scanning: ./myproject
Type: directory

Scan Complete
=============

Weak cryptographic issues found: 3
Security score: 76%

Issues:

[1] MEDIUM - Weak Cryptographic Algorithm
    File: ./config/settings.yaml
    Description: SHA-1 has known collision vulnerabilities
    Recommendation: Replace with SHA-256 or SHA-3

[2] CRITICAL - Weak Cryptographic Algorithm
    File: ./auth/encryption.go
    Description: MD5 hash function is cryptographically broken
    Recommendation: Replace with SHA-256 or SHA-3

[3] HIGH - Weak Cryptographic Algorithm
    File: ./legacy/des_config.txt
    Description: DES uses 56-bit key, easily brute-forced
    Recommendation: Replace with AES-256
```

## 🔒 Compliance

This tool helps verify compliance with:

- **NIST SP 800-131A** - Transitioning Cryptographic Algorithms
- **PCI-DSS** - Payment Card Industry Data Security Standard
- **CIS Benchmarks** - Center for Internet Security
- **OWASP Cryptographic Cheat Sheet**

## 🏗️ Architecture

```
cryptoaudit/
├── cmd/
│   └── cryptoaudit/
│       └── main.go          # CLI entry point
├── pkg/
│   └── crypto/
│       ├── crypto.go        # Cryptographic analysis
│       └── crypto_test.go   # Unit tests
└── README.md
```

## ⚠️ Disclaimer

This tool is for security auditing and compliance checking only. Always verify findings manually before making production changes.

## 📄 License

MIT License

## 🙏 Acknowledgments

- NIST Cryptographic Standards
- OWASP Security Guidelines
- Security researchers sharing vulnerability data

---

**Built with ❤️ by [hallucinaut](https://github.com/hallucinaut)**