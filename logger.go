//simple logger package built on Lumberjack and Go's bulit-in Log
package logger

import (
	"gopkg.in/natefinch/lumberjack.v2"
	"io"
	"log"
	"os"
)

type Logger struct {
	Level      string
	Filename   string
	MaxSize    int
	MaxBackUps int
	MaxAge     int
	debug      log.Logger
	info       log.Logger
	warning    log.Logger
	error      log.Logger
	isInit     bool
}

//Initializes logger for first user
func (l *Logger) Init() {
	//set default values if not given
	if l.Filename == "" {
		l.Filename = "default.log"
	}

	if l.MaxSize == 0 {
		l.MaxSize = 100
	}

	if l.MaxAge == 0 {
		l.MaxAge = 28
	}

	if l.MaxBackUps == 0 {
		l.MaxBackUps = 3
	}

	if l.Level == "" {
		l.Level = "DEBUG"
	}

	//set up the logging function
	lj := lumberjack.Logger{
		Filename:   l.Filename,
		MaxSize:    l.MaxSize, // megabytes
		MaxBackups: l.MaxBackUps,
		MaxAge:     l.MaxAge, //days
		LocalTime:  true,
	}
	mw := io.MultiWriter(os.Stdout, &lj)

	l.debug = log.Logger{}
	l.debug.SetPrefix("[DEBUG]\t")
	l.debug.SetFlags(log.LstdFlags | log.LUTC)
	l.debug.SetOutput(mw)

	l.info = log.Logger{}
	l.info.SetPrefix("[INFO]\t")
	l.info.SetFlags(log.LstdFlags | log.LUTC)
	l.info.SetOutput(mw)

	l.warning = log.Logger{}
	l.warning.SetPrefix("[WARN]\t")
	l.warning.SetFlags(log.LstdFlags | log.LUTC)
	l.warning.SetOutput(mw)

	l.error = log.Logger{}
	l.error.SetPrefix("[ERROR]\t")
	l.error.SetFlags(log.LstdFlags | log.LUTC)
	l.error.SetOutput(mw)

	//mark as initialized
	l.isInit = true
}

//Logs debug messages
func (l *Logger) Debug(text string, args ...interface{}) {
	if !l.isInit {
		l.Init()
	}
	if l.Level == "DEBUG" {
		l.debug.Printf(text, args...)
	}
}

//Logs info messages
func (l *Logger) Info(text string, args ...interface{}) {
	if !l.isInit {
		l.Init()
	}
	if l.Level == "DEBUG" || l.Level == "INFO" {
		l.info.Printf(text, args...)
	}
}

//Logs warning messages
func (l *Logger) Warn(text string, args ...interface{}) {
	if !l.isInit {
		l.Init()
	}
	if l.Level == "DEBUG" || l.Level == "INFO" || l.Level == "WARN" {
		l.warning.Printf(text, args...)
	}
}

//Logs error messages
func (l *Logger) Error(text string, args ...interface{}) {
	if !l.isInit {
		l.Init()
	}
	//always show error messages
	l.error.Printf(text, args...)
}
