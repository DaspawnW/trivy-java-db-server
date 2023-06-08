package configuration

import (
	"errors"
	"flag"
	"fmt"
	"github.com/sirupsen/logrus"
)

type Options struct {
	DBDir         string
	ListenAddress string
	LogLevel      string
	PrintVersion  bool
}

func LoadOptions() (*Options, error) {
	// /Users/bjoernwenzel/Library/Caches/trivy/java-db
	dbDir := flag.String("trivy-java-db-dir", "", "Directory of trivy java database")
	addr := flag.String("listen", "0.0.0.0:50051", "Port the server listens on")
	logLevel := flag.String("log-level", "INFO", "Increase log level to DEBUG")
	printVersion := flag.Bool("version", false, "Print version information")
	flag.Parse()

	if dbDir == nil || len(*dbDir) == 0 {
		return nil, errors.New("trivy-java-db-dir flag not defined")
	}

	if err := setLogLevel(*logLevel); err != nil {
		return nil, err
	}

	return &Options{
		DBDir:         *dbDir,
		ListenAddress: *addr,
		LogLevel:      *logLevel,
		PrintVersion:  *printVersion,
	}, nil
}

func setLogLevel(logLevel string) error {
	switch logLevel {
	case "INFO":
		logrus.SetLevel(logrus.InfoLevel)
		return nil
	case "DEBUG":
		logrus.SetLevel(logrus.DebugLevel)
		return nil
	default:
		return fmt.Errorf("Log level %s unknown", logLevel)
	}
}
