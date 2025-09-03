package utils

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

type Logger struct {
	verbose  bool
	colors   map[string]*color.Color
	file     *os.File
	mu       sync.Mutex
}

func NewLogger(verbose bool) *Logger {
	logger := &Logger{
		verbose: verbose,
		colors: map[string]*color.Color{
			"info":    color.New(color.FgBlue),
			"success": color.New(color.FgGreen),
			"warning": color.New(color.FgYellow),
			"error":   color.New(color.FgRed),
			"debug":   color.New(color.FgMagenta),
		},
	}

	// Create logs directory if it doesn't exist
	if err := os.MkdirAll("logs", 0755); err == nil {
		// Create log file with timestamp
		timestamp := time.Now().Format("20060102_150405")
		if file, err := os.Create(filepath.Join("logs", fmt.Sprintf("acva_%s.log", timestamp))); err == nil {
			logger.file = file
		}
	}

	return logger
}

func (l *Logger) Close() {
	if l.file != nil {
		l.file.Close()
	}
}

func (l *Logger) log(level, format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf(format, args...)
	logLine := fmt.Sprintf("[%s] %s: %s\n", timestamp, strings.ToUpper(level), message)

	// Write to console with colors
	if l.colors[level] != nil {
		l.colors[level].Printf("[%s] %s: %s\n", timestamp, strings.ToUpper(level), message)
	} else {
		fmt.Printf(logLine)
	}

	// Write to file
	if l.file != nil {
		l.file.WriteString(logLine)
	}
}

func (l *Logger) Info(format string, args ...interface{}) {
	l.log("info", format, args...)
}

func (l *Logger) Success(format string, args ...interface{}) {
	l.log("success", format, args...)
}

func (l *Logger) Warning(format string, args ...interface{}) {
	l.log("warning", format, args...)
}

func (l *Logger) Error(format string, args ...interface{}) {
	l.log("error", format, args...)
}

func (l *Logger) Debug(format string, args ...interface{}) {
	if l.verbose {
		l.log("debug", format, args...)
	}
}

func (l *Logger) Fatal(format string, args ...interface{}) {
	l.log("error", format, args...)
	os.Exit(1)
}
