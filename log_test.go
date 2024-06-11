package main

import (
	"testing"

	"github.com/renyangang/gotools/logger"
)

func TestLog(t *testing.T) {
	logger.Init("./logs", "app", 7, 1*1024*1024, logger.INFO)
	logger.Info("std output log")
}

func TestLogNoStdOut(t *testing.T) {
	logger.InitIfStdOut("./logs", "app", 7, 1*1024*1024, logger.INFO, false)
	logger.Info("no std output log")
}
