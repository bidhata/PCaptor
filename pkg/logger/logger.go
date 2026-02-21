package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

// Level represents log level
type Level int

const (
	DEBUG Level = iota
	INFO
	WARN
	ERROR
)

var levelNames = map[Level]string{
	DEBUG: "DEBUG",
	INFO:  "INFO",
	WARN:  "WARN",
	ERROR: "ERROR",
}

var levelColors = map[Level]string{
	DEBUG: "\033[36m", // Cyan
	INFO:  "\033[32m", // Green
	WARN:  "\033[33m", // Yellow
	ERROR: "\033[31m", // Red
}

const colorReset = "\033[0m"

// Logger represents a logger instance
type Logger struct {
	level      Level
	output     io.Writer
	fileOutput *os.File
	useColor   bool
}

// New creates a new logger
func New(level string, logFile string) (*Logger, error) {
	l := &Logger{
		level:    parseLevel(level),
		output:   os.Stdout,
		useColor: true,
	}

	// Open log file if specified
	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		l.fileOutput = f
	}

	return l, nil
}

// Close closes the logger
func (l *Logger) Close() error {
	if l.fileOutput != nil {
		return l.fileOutput.Close()
	}
	return nil
}

func parseLevel(level string) Level {
	switch level {
	case "debug":
		return DEBUG
	case "info":
		return INFO
	case "warn":
		return WARN
	case "error":
		return ERROR
	default:
		return INFO
	}
}

func (l *Logger) log(level Level, format string, args ...interface{}) {
	if level < l.level {
		return
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	levelName := levelNames[level]
	message := fmt.Sprintf(format, args...)

	// Console output with color
	if l.useColor {
		color := levelColors[level]
		fmt.Fprintf(l.output, "%s [%s%s%s] %s\n", timestamp, color, levelName, colorReset, message)
	} else {
		fmt.Fprintf(l.output, "%s [%s] %s\n", timestamp, levelName, message)
	}

	// File output without color
	if l.fileOutput != nil {
		fmt.Fprintf(l.fileOutput, "%s [%s] %s\n", timestamp, levelName, message)
	}
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(DEBUG, format, args...)
}

// Info logs an info message
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(INFO, format, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(format string, args ...interface{}) {
	l.log(WARN, format, args...)
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(ERROR, format, args...)
}

// Fatal logs a fatal error and exits
func (l *Logger) Fatal(format string, args ...interface{}) {
	l.log(ERROR, format, args...)
	if l.fileOutput != nil {
		l.fileOutput.Close()
	}
	os.Exit(1)
}

// SetLevel sets the log level
func (l *Logger) SetLevel(level string) {
	l.level = parseLevel(level)
}

// Default logger for backward compatibility
var defaultLogger *Logger

func init() {
	defaultLogger, _ = New("info", "")
}

// Debug logs a debug message using the default logger
func Debug(format string, args ...interface{}) {
	defaultLogger.Debug(format, args...)
}

// Info logs an info message using the default logger
func Info(format string, args ...interface{}) {
	defaultLogger.Info(format, args...)
}

// Warn logs a warning message using the default logger
func Warn(format string, args ...interface{}) {
	defaultLogger.Warn(format, args...)
}

// Error logs an error message using the default logger
func Error(format string, args ...interface{}) {
	defaultLogger.Error(format, args...)
}

// Fatal logs a fatal error and exits using the default logger
func Fatal(format string, args ...interface{}) {
	defaultLogger.Fatal(format, args...)
}

// SetDefault sets the default logger
func SetDefault(l *Logger) {
	defaultLogger = l
}

// Compatibility with standard log package
func init() {
	log.SetFlags(0)
	log.SetOutput(os.Stdout)
}
