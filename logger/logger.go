package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	ERROR = iota
	INFO
	DEBUG
)

var LogLevel int = INFO
var GLogger *Logger

type Logger struct {
	LogDir        string
	LogNamePrefix string
	logPath       string
	logFile       *os.File
	LogRemainDays int
	MaxLogSize    int64
	isInit        bool
}

func Init(logDir string, logNamePrefix string, logRemainDays int, maxLogSize int64, logLevel int) {
	InitIfStdOut(logDir, logNamePrefix, logRemainDays, maxLogSize, logLevel, true)
}

func InitIfStdOut(logDir string, logNamePrefix string, logRemainDays int, maxLogSize int64, logLevel int, isStdOut bool) {
	GLogger = &Logger{
		LogDir:        logDir,
		LogNamePrefix: logNamePrefix,
		LogRemainDays: logRemainDays,
		MaxLogSize:    maxLogSize,
		isInit:        false,
	}
	LogLevel = logLevel
	if isStdOut {
		log.SetOutput(io.MultiWriter(GLogger, os.Stdout))
	} else {
		log.SetOutput(GLogger)
	}
	log.SetFlags(0)
}

func SetLogDir(logDir string) {
	GLogger.LogDir = logDir
}

func SetNamePrefix(logNamePrefix string) {
	GLogger.LogNamePrefix = logNamePrefix
}

func SetLogRemainDays(logRemainDays int) {
	GLogger.LogRemainDays = logRemainDays
}

func SetMaxLogSize(maxLogSize int64) {
	GLogger.MaxLogSize = maxLogSize
}

func SetLogLevel(logLevel int) {
	LogLevel = logLevel
}

// 清理过期文件
func (logger *Logger) rmOldFilesInDirectoryLoop() {
	for {
		exrisTime := time.Now().AddDate(0, 0, -1*logger.LogRemainDays)
		filepath.Walk(logger.LogDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || strings.LastIndex(info.Name(), ".log") != len(info.Name())-4 {
				return nil // 忽略目录和非log文件
			}
			if info.ModTime().Before(exrisTime) {
				os.Remove(path)
			}
			return nil
		})
		time.Sleep(1 * time.Hour) // 每小时检查一次
	}
}

func (logger *Logger) init() {
	if !logger.isInit {
		if _, err := os.Stat(logger.LogDir); os.IsNotExist(err) {
			err := os.Mkdir(logger.LogDir, 0755)
			if err != nil {
				log.Fatalf("Failed to create directory: %v", err)
			}
		}
		go logger.rmOldFilesInDirectoryLoop()
		logger.logPath = filepath.Join(logger.LogDir, logger.LogNamePrefix+".log")
		logger.isInit = true
	}
}

func (logger *Logger) check() {
	logger.init()
	if fileInfo, err := os.Stat(logger.logPath); os.IsNotExist(err) || logger.logFile == nil {
		logger.createLogFile()
	} else if fileInfo.Size() >= logger.MaxLogSize {
		os.Rename(logger.logPath, filepath.Join(logger.LogDir, logger.LogNamePrefix+"_"+time.Now().Format("20060102150405")+".log"))
		logger.createLogFile()
	} else {
		return
	}
}

func (logger *Logger) createLogFile() {
	if logger.logFile != nil {
		logger.logFile.Close()
	}
	lf, err := os.OpenFile(logger.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("Error opening log file: %v", err)
	}
	logger.logFile = lf
}

func (logger *Logger) Write(p []byte) (n int, err error) {
	logger.check()
	return logger.logFile.Write(p)
}

func getCallerInfo(skip int) (info string) {
	_, file, lineNo, ok := runtime.Caller(skip)
	if !ok {

		info = "runtime.Caller() failed"
		return
	}
	fileName := path.Base(file) // Base函数返回路径的最后一个元素
	now := time.Now()
	// 使用自定义格式字符串格式化时间
	formattedTime := now.Format("2006-01-02 15:04:05")
	return fmt.Sprintf("%s file:%s, line:%d ", formattedTime, fileName, lineNo)
}

func Info(msg string, args ...any) {
	if LogLevel >= INFO {
		doLogDirect("INFO", msg, args...)
	}
}

func Error(msg string, args ...any) {
	if LogLevel >= ERROR {
		doLogDirect("ERROR", msg, args...)
	}
}

func Debug(msg string, args ...any) {
	if LogLevel >= DEBUG {
		doLogDirect("DEBUG", msg, args...)
	}
}

func doLogDirect(level string, msg string, args ...any) {
	log.SetPrefix("[" + level + "] " + getCallerInfo(3) + " ")
	log.Printf(msg+"\n", args...)
}

func Writer() io.Writer {
	return log.Writer()
}
