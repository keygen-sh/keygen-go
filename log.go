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

var DefaultLogger LoggerInterface = &LeveledLogger{Level: LogLevelError}

type LeveledLogger struct {
	Level LogLevel
}

func (l *LeveledLogger) Errorf(format string, v ...interface{}) {
	if l.Level < LogLevelError {
		return
	}

	fmt.Fprintf(os.Stderr, "[ERROR] "+format+"\n", v...)
}

func (l *LeveledLogger) Warnf(format string, v ...interface{}) {
	if l.Level < LogLevelWarn {
		return
	}

	fmt.Fprintf(os.Stderr, "[WARN] "+format+"\n", v...)
}

func (l *LeveledLogger) Infof(format string, v ...interface{}) {
	if l.Level < LogLevelInfo {
		return
	}

	fmt.Fprintf(os.Stdout, "[INFO] "+format+"\n", v...)
}

func (l *LeveledLogger) Debugf(format string, v ...interface{}) {
	if l.Level < LogLevelDebug {
		return
	}

	fmt.Fprintf(os.Stdout, "[DEBUG] "+format+"\n", v...)
}

// LoggerInterface provides a basic leveled logging interface for
// printing debug, informational, warning, and error messages.
type LoggerInterface interface {
	// Debugf logs a debug message using Printf conventions.
	Debugf(format string, v ...interface{})

	// Errorf logs a warning message using Printf conventions.
	Errorf(format string, v ...interface{})

	// Infof logs an informational message using Printf conventions.
	Infof(format string, v ...interface{})

	// Warnf logs a warning message using Printf conventions.
	Warnf(format string, v ...interface{})
}
