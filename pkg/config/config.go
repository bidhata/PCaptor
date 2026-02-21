package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config represents the application configuration
type Config struct {
	Analysis  AnalysisConfig  `json:"analysis"`
	Detection DetectionConfig `json:"detection"`
	Output    OutputConfig    `json:"output"`
	Logging   LoggingConfig   `json:"logging"`
}

// AnalysisConfig contains analysis settings
type AnalysisConfig struct {
	Workers     int `json:"workers"`
	MaxFlows    int `json:"max_flows"`
	MaxMessages int `json:"max_messages"`
}

// DetectionConfig contains detection settings
type DetectionConfig struct {
	Beaconing BeaconingConfig `json:"beaconing"`
	C2        C2Config        `json:"c2"`
	TLS       TLSConfig       `json:"tls"`
}

// BeaconingConfig contains beaconing detection settings
type BeaconingConfig struct {
	Enabled         bool    `json:"enabled"`
	MinPackets      int     `json:"min_packets"`
	JitterThreshold float64 `json:"jitter_threshold"`
}

// C2Config contains C2 detection settings
type C2Config struct {
	Enabled    bool     `json:"enabled"`
	Frameworks []string `json:"frameworks"`
}

// TLSConfig contains TLS fingerprinting settings
type TLSConfig struct {
	Enabled bool `json:"enabled"`
}

// OutputConfig contains output settings
type OutputConfig struct {
	HTML      bool   `json:"html"`
	CSV       bool   `json:"csv"`
	JSON      bool   `json:"json"`
	Directory string `json:"directory"`
}

// LoggingConfig contains logging settings
type LoggingConfig struct {
	Level string `json:"level"`
	File  string `json:"file"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		Analysis: AnalysisConfig{
			Workers:     0, // 0 means use CPU count
			MaxFlows:    1000000,
			MaxMessages: 100000,
		},
		Detection: DetectionConfig{
			Beaconing: BeaconingConfig{
				Enabled:         true,
				MinPackets:      10,
				JitterThreshold: 0.5,
			},
			C2: C2Config{
				Enabled: true,
				Frameworks: []string{
					"cobalt_strike",
					"metasploit",
					"empire",
					"covenant",
					"sliver",
					"mythic",
					"brute_ratel",
					"poshc2",
					"havoc",
					"pupy",
					"koadic",
				},
			},
			TLS: TLSConfig{
				Enabled: true,
			},
		},
		Output: OutputConfig{
			HTML:      false,
			CSV:       false,
			JSON:      false,
			Directory: "",
		},
		Logging: LoggingConfig{
			Level: "info",
			File:  "",
		},
	}
}

// LoadConfig loads configuration from a file
func LoadConfig(path string) (*Config, error) {
	// Check if file exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file not found: %s", path)
	}

	// Read file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse JSON
	config := DefaultConfig()
	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return config, nil
}

// SaveConfig saves configuration to a file
func SaveConfig(config *Config, path string) error {
	// Create directory if needed
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write file
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Analysis.Workers < 0 {
		return fmt.Errorf("workers must be >= 0")
	}
	if c.Analysis.MaxFlows < 1000 {
		return fmt.Errorf("max_flows must be >= 1000")
	}
	if c.Analysis.MaxMessages < 1000 {
		return fmt.Errorf("max_messages must be >= 1000")
	}
	if c.Detection.Beaconing.MinPackets < 3 {
		return fmt.Errorf("beaconing min_packets must be >= 3")
	}
	if c.Detection.Beaconing.JitterThreshold < 0 || c.Detection.Beaconing.JitterThreshold > 1 {
		return fmt.Errorf("beaconing jitter_threshold must be between 0 and 1")
	}
	if c.Logging.Level != "debug" && c.Logging.Level != "info" && c.Logging.Level != "warn" && c.Logging.Level != "error" {
		return fmt.Errorf("logging level must be one of: debug, info, warn, error")
	}
	return nil
}
