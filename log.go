package keygen

import (
	"fmt"
	"io"
	"os"
)

type LogLevel uint32

const (
	LogLevelNone LogLevel = iota
	LogLevelError
	LogLevelWarn
	LogLevelInfo
	LogLevelDebug
)

// LoggerOptions stores config options used for the logger e.g. log streams.
type LoggerOptions struct {
	Stdout io.Writer
	Stderr io.Writer
}

type logger struct {
	Level LogLevel
	LoggerOptions
}

func (l *logger) Errorf(format string, v ...interface{}) {
	if l.Level < LogLevelError {
		return
	}

	fmt.Fprintf(l.Stderr, "[ERROR] "+format+"\n", v...)
}

func (l *logger) Warnf(format string, v ...interface{}) {
	if l.Level < LogLevelWarn {
		return
	}

	fmt.Fprintf(l.Stderr, "[WARN] "+format+"\n", v...)
}

func (l *logger) Infof(format string, v ...interface{}) {
	if l.Level < LogLevelInfo {
		return
	}

	fmt.Fprintf(l.Stdout, "[INFO] "+format+"\n", v...)
}

func (l *logger) Debugf(format string, v ...interface{}) {
	if l.Level < LogLevelDebug {
		return
	}

	fmt.Fprintf(l.Stdout, "[DEBUG] "+format+"\n", v...)
}

// LeveledLogger provides a basic leveled logging interface for
// printing debug, informational, warning, and error messages.
type LeveledLogger interface {
	// Errorf logs a warning message using Printf conventions.
	Errorf(format string, v ...interface{})

	// Warnf logs a warning message using Printf conventions.
	Warnf(format string, v ...interface{})

	// Infof logs an informational message using Printf conventions.
	Infof(format string, v ...interface{})

	// Debugf logs a debug message using Printf conventions.
	Debugf(format string, v ...interface{})
}

// NewClient creates a new leveled logger with default log streams to stdout and stderr.
func NewLogger(level LogLevel) LeveledLogger {
	return &logger{level, LoggerOptions{os.Stdout, os.Stderr}}
}

// NewLoggerWithOptions creates a new leveled logger with custom log streams.
func NewLoggerWithOptions(level LogLevel, options *LoggerOptions) LeveledLogger {
	return &logger{level, *options}
}

// NewNilLogger creates a new leveled logger with discarded log steams.
func NewNilLogger() LeveledLogger {
	return &logger{LogLevelNone, LoggerOptions{io.Discard, io.Discard}}
}
