package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/hallucinaut/cryptoaudit/pkg/crypto"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	switch os.Args[1] {
	case "scan":
		if len(os.Args) < 3 {
			fmt.Println("Error: target path required")
			printUsage()
			return
		}
		scanTarget(os.Args[2])
	case "check":
		if len(os.Args) < 3 {
			fmt.Println("Error: target path required")
			printUsage()
			return
		}
		checkConfig(os.Args[2])
	case "version":
		fmt.Printf("cryptoaudit version %s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		printUsage()
	}
}

func printUsage() {
	fmt.Printf(`cryptoaudit - Cryptographic Weakness Scanner

Usage:
  cryptoaudit <command> [options]

Commands:
  scan <path>     Recursively scan files for weak cryptographic patterns
  check <path>    Check configuration files for crypto issues
  version         Show version information
  help            Show this help message

Examples:
  cryptoaudit scan ./myproject
  cryptoaudit scan /etc/ssl
  cryptoaudit check config.yaml
`,)
}

func scanTarget(target string) {
	scanner := crypto.NewScanner()
	
	info, err := os.Stat(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Scanning: %s\n", target)
	fmt.Printf("Type: %s\n\n", getType(info))

	var allIssues []crypto.ConfigIssue
	var visitedDirs map[string]bool
	visitedDirs = make(map[string]bool)

	if info.IsDir() {
		err = filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			
			// Skip directories
			if info.IsDir() {
				// Skip common non-source directories
				if info.Name() == ".git" || info.Name() == "node_modules" ||
				   info.Name() == "vendor" || info.Name() == "dist" ||
				   info.Name() == "build" {
					return filepath.SkipDir
				}
				return nil
			}

			// Skip binary files
			if isBinary(info) {
				return nil
			}

			// Skip if directory already visited
			dir := filepath.Dir(path)
			if visitedDirs[dir] {
				return nil
			}
			visitedDirs[dir] = true

			// Read file
			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			// Scan for issues
			issues := scanner.ScanContent(string(content))
			for i := range issues {
				issues[i].File = path
			}
			allIssues = append(allIssues, issues...)

			return nil
		})
	} else {
		content, err := os.ReadFile(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
			os.Exit(1)
		}

		issues := scanner.ScanContent(string(content))
		for i := range issues {
			issues[i].File = target
		}
		allIssues = append(allIssues, issues...)
	}

	// Calculate score
	score := crypto.CalculateScore(allIssues)

	fmt.Printf("Scan Complete\n")
	fmt.Printf("=============\n\n")
	fmt.Printf("Weak cryptographic issues found: %d\n", len(allIssues))
	fmt.Printf("Security score: %.0f%%\n\n", score)

	if len(allIssues) > 0 {
		fmt.Println("Issues:")
		fmt.Println("-------")
		
		for i, issue := range allIssues {
			severity := issue.Severity
			if severity == "critical" {
				severity = "CRITICAL"
			} else if severity == "high" {
				severity = "HIGH"
			} else if severity == "medium" {
				severity = "MEDIUM"
			} else {
				severity = "LOW"
			}
			
			fmt.Printf("\n[%d] %s - %s\n", i+1, severity, issue.Type)
			fmt.Printf("    File: %s\n", issue.File)
			fmt.Printf("    Description: %s\n", issue.Description)
			fmt.Printf("    Recommendation: %s\n", issue.Recommendation)
		}
	} else {
		fmt.Println("No weak cryptographic patterns detected!")
	}
}

func checkConfig(filepath string) {
	scanner := crypto.NewScanner()
	
	content, err := os.ReadFile(filepath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Checking: %s\n", filepath)
	fmt.Println()

	issues := scanner.ScanContent(string(content))

	if len(issues) == 0 {
		fmt.Println("✓ No cryptographic issues found in configuration")
	} else {
		fmt.Printf("Found %d cryptographic issues:\n\n", len(issues))
		
		for i, issue := range issues {
			fmt.Printf("[%d] %s: %s\n", i+1, issue.Type, issue.Description)
			fmt.Printf("    Recommendation: %s\n", issue.Recommendation)
			fmt.Println()
		}
	}
}

func getType(info os.FileInfo) string {
	if info.IsDir() {
		return "directory"
	}
	return "file"
}

func isBinary(info os.FileInfo) bool {
	// Skip files larger than 10MB
	if info.Size() > 10*1024*1024 {
		return true
	}
	
	// In a real implementation, would check file magic bytes
	// For now, skip very small files that might be binary
	return info.Size() < 100
}