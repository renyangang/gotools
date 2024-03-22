package main

import "github.com/renyangang/gotools/logger"

func init() { // 初始化日志
	logger.Init("./logs", "app", 7, 1*1024*1024, logger.INFO)
}

func main() {
	logger.Info("Hello, world!")
}
