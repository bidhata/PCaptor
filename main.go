package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/bidhata/PCaptor/pkg/analyzer"
	"github.com/bidhata/PCaptor/pkg/config"
	"github.com/bidhata/PCaptor/pkg/logger"
)

const (
	version = "2.0.0"
	author  = "Krishnendu Paul (@bidhata)"
	website = "https://krishnendu.com"
	github  = "https://github.com/bidhata/PCaptor"
)

// Exit codes
const (
	ExitSuccess         = 0
	ExitGeneralError    = 1
	ExitFileNotFound    = 2
	ExitInvalidFormat   = 3
	ExitPermissionError = 4
	ExitConfigError     = 5
	ExitAnalysisError   = 6
	ExitInterrupted     = 130
)

var log *logger.Logger

func main() {
	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Command line flags
	pcapFile := flag.String("f", "", "PCAP file to analyze (required)")
	outputDir := flag.String("o", "", "Output directory for reports")
	workers := flag.Int("w", runtime.NumCPU(), "Number of worker goroutines")
	exportHTML := flag.Bool("html", false, "Export HTML report")
	exportJSON := flag.Bool("json", false, "Export JSON report")
	exportCSV := flag.Bool("csv", false, "Export CSV report")
	showVersion := flag.Bool("version", false, "Show version information")
	configFile := flag.String("config", "", "Configuration file (JSON)")
	logLevel := flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	logFile := flag.String("log-file", "", "Log file path")
	quiet := flag.Bool("q", false, "Quiet mode (minimal output)")
	verbose := flag.Bool("v", false, "Verbose mode (detailed output)")
	generateConfig := flag.Bool("generate-config", false, "Generate default configuration file")

	flag.Parse()

	// Initialize logger
	var err error
	if *verbose {
		*logLevel = "debug"
	} else if *quiet {
		*logLevel = "error"
	}
	
	log, err = logger.New(*logLevel, *logFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(ExitGeneralError)
	}
	defer log.Close()
	logger.SetDefault(log)

	// Show version
	if *showVersion {
		fmt.Printf("PCaptor v%s\n", version)
		fmt.Printf("Author: %s\n", author)
		fmt.Printf("Website: %s\n", website)
		fmt.Printf("GitHub: %s\n\n", github)
		fmt.Printf("Build Info:\n")
		fmt.Printf("  Go Version: %s\n", runtime.Version())
		fmt.Printf("  OS/Arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		fmt.Printf("  CPUs: %d\n", runtime.NumCPU())
		os.Exit(ExitSuccess)
	}

	// Generate config
	if *generateConfig {
		cfg := config.DefaultConfig()
		configPath := "pcaptor.json"
		if *configFile != "" {
			configPath = *configFile
		}
		if err := config.SaveConfig(cfg, configPath); err != nil {
			log.Error("Failed to generate config: %v", err)
			os.Exit(ExitConfigError)
		}
		log.Info("Configuration file generated: %s", configPath)
		os.Exit(ExitSuccess)
	}

	// Load configuration if specified
	var cfg *config.Config
	if *configFile != "" {
		cfg, err = config.LoadConfig(*configFile)
		if err != nil {
			log.Error("Failed to load config: %v", err)
			os.Exit(ExitConfigError)
		}
		if err := cfg.Validate(); err != nil {
			log.Error("Invalid configuration: %v", err)
			os.Exit(ExitConfigError)
		}
		log.Info("Loaded configuration from: %s", *configFile)
		
		// Apply config settings
		if cfg.Analysis.Workers > 0 {
			*workers = cfg.Analysis.Workers
		}
		if cfg.Output.HTML {
			*exportHTML = true
		}
		if cfg.Output.CSV {
			*exportCSV = true
		}
		if cfg.Output.JSON {
			*exportJSON = true
		}
		if cfg.Output.Directory != "" && *outputDir == "" {
			*outputDir = cfg.Output.Directory
		}
	}

	// CLI mode
	if *pcapFile != "" {
		exitCode := runCLI(*pcapFile, *outputDir, *workers, *exportHTML, *exportJSON, *exportCSV, sigChan)
		os.Exit(exitCode)
	}

	// No file specified - show usage
	fmt.Println("PCaptor v" + version + " - Advanced Network Packet Analyzer")
	fmt.Println("\nUsage: pcaptor -f <pcap_file> [options]")
	fmt.Println("\nRequired:")
	fmt.Println("  -f string")
	fmt.Println("        PCAP file to analyze")
	fmt.Println("\nOutput Options:")
	fmt.Println("  -html")
	fmt.Println("        Export HTML report")
	fmt.Println("  -csv")
	fmt.Println("        Export CSV reports")
	fmt.Println("  -json")
	fmt.Println("        Export JSON report")
	fmt.Println("  -o string")
	fmt.Println("        Output directory for reports")
	fmt.Println("\nAnalysis Options:")
	fmt.Println("  -w int")
	fmt.Println("        Number of worker goroutines (default: CPU count)")
	fmt.Println("  -config string")
	fmt.Println("        Configuration file (JSON)")
	fmt.Println("\nLogging Options:")
	fmt.Println("  -log-level string")
	fmt.Println("        Log level: debug, info, warn, error (default: info)")
	fmt.Println("  -log-file string")
	fmt.Println("        Log file path")
	fmt.Println("  -q    Quiet mode (minimal output)")
	fmt.Println("  -v    Verbose mode (detailed output)")
	fmt.Println("\nOther Options:")
	fmt.Println("  -version")
	fmt.Println("        Show version information")
	fmt.Println("  -generate-config")
	fmt.Println("        Generate default configuration file")
	fmt.Println("\nExamples:")
	fmt.Println("  pcaptor -f capture.pcap -html")
	fmt.Println("  pcaptor -f capture.pcap -html -csv -json")
	fmt.Println("  pcaptor -f capture.pcap -config pcaptor.json")
	fmt.Println("  pcaptor -generate-config")
	fmt.Println("\nFor more information, visit: " + github)
	os.Exit(ExitGeneralError)
}

func runCLI(pcapFile, outputDir string, workers int, html, json, csv bool, sigChan chan os.Signal) int {
	startTime := time.Now()
	
	log.Info("PCaptor v%s - Analyzing %s", version, pcapFile)
	log.Info("Workers: %d", workers)

	// Check if file exists
	if _, err := os.Stat(pcapFile); os.IsNotExist(err) {
		log.Error("File not found: %s", pcapFile)
		return ExitFileNotFound
	}

	// Check file permissions
	if _, err := os.Open(pcapFile); err != nil {
		log.Error("Permission denied: %s", err)
		return ExitPermissionError
	}

	// Create analyzer
	log.Debug("Creating analyzer...")
	a := analyzer.New(pcapFile, outputDir, workers)

	// Run analysis in goroutine to handle interrupts
	done := make(chan error, 1)
	go func() {
		done <- a.Analyze()
	}()

	// Wait for completion or interrupt
	select {
	case err := <-done:
		if err != nil {
			log.Error("Analysis failed: %v", err)
			return ExitAnalysisError
		}
		log.Info("Analysis completed successfully")
	case sig := <-sigChan:
		log.Warn("Received signal: %v", sig)
		log.Warn("Gracefully shutting down...")
		// Give analyzer time to finish current packet
		time.Sleep(100 * time.Millisecond)
		return ExitInterrupted
	}

	// Export reports
	exportErrors := 0
	
	if html {
		log.Info("Exporting HTML report...")
		if err := a.ExportHTML(); err != nil {
			log.Error("HTML export failed: %v", err)
			exportErrors++
		} else {
			log.Info("HTML report exported successfully")
		}
	}

	if json {
		log.Info("Exporting JSON report...")
		if err := a.ExportJSON(); err != nil {
			log.Error("JSON export failed: %v", err)
			exportErrors++
		} else {
			log.Info("JSON report exported successfully")
		}
	}

	if csv {
		log.Info("Exporting CSV reports...")
		if err := a.ExportCSV(); err != nil {
			log.Error("CSV export failed: %v", err)
			exportErrors++
		} else {
			log.Info("CSV reports exported successfully")
		}
	}

	// Print summary
	fmt.Println()
	a.PrintSummary()
	
	elapsed := time.Since(startTime)
	log.Info("Total execution time: %v", elapsed)

	if exportErrors > 0 {
		log.Warn("Completed with %d export error(s)", exportErrors)
		return ExitGeneralError
	}

	return ExitSuccess
}
