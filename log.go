package keygen

import (
	"fmt"
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

type logger struct {
	Level LogLevel
}

func (l *logger) Errorf(format string, v ...interface{}) {
	if l.Level < LogLevelError {
		return
	}

	fmt.Fprintf(os.Stderr, "[ERROR] "+format+"\n", v...)
}

func (l *logger) Warnf(format string, v ...interface{}) {
	if l.Level < LogLevelWarn {
		return
	}

	fmt.Fprintf(os.Stderr, "[WARN] "+format+"\n", v...)
}

func (l *logger) Infof(format string, v ...interface{}) {
	if l.Level < LogLevelInfo {
		return
	}

	fmt.Fprintf(os.Stdout, "[INFO] "+format+"\n", v...)
}

func (l *logger) Debugf(format string, v ...interface{}) {
	if l.Level < LogLevelDebug {
		return
	}

	fmt.Fprintf(os.Stdout, "[DEBUG] "+format+"\n", v...)
}

// LeveledLogger provides a basic leveled logging interface for
// printing debug, informational, warning, and error messages.
type LeveledLogger interface {
	// Debugf logs a debug message using Printf conventions.
	Debugf(format string, v ...interface{})

	// Errorf logs a warning message using Printf conventions.
	Errorf(format string, v ...interface{})

	// Infof logs an informational message using Printf conventions.
	Infof(format string, v ...interface{})

	// Warnf logs a warning message using Printf conventions.
	Warnf(format string, v ...interface{})
}
