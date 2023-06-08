package main

import (
	"github.com/daspawnw/trivy-java-db-server/pkg/configuration"
	"github.com/daspawnw/trivy-java-db-server/pkg/server"
	"github.com/daspawnw/trivy-java-db-server/pkg/serverpb"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	_ "modernc.org/sqlite"
	"net"
	"os"
)

var VERSION = "development"

func main() {
	opts, err := configuration.LoadOptions()
	if err != nil {
		logrus.Errorf("Configuration loading failed with error %v", err)
		os.Exit(1)
	}

	if opts.PrintVersion {
		logrus.Infof("github.com/daspawnw/trivy-java-db-server in version %s", VERSION)
		os.Exit(0)
	}

	lis, err := net.Listen("tcp", opts.ListenAddress)
	if err != nil {
		logrus.Errorf("Failed to listen on address %s with error %v", opts.ListenAddress, err)
		os.Exit(1)
	}

	logrus.Infof("Start listening on %s", opts.ListenAddress)

	var serverOpts []grpc.ServerOption
	grpcServer := grpc.NewServer(serverOpts...)
	grpc_health_v1.RegisterHealthServer(grpcServer, health.NewServer())

	javaServer, err := server.NewTrivyJavaDBServer(opts.DBDir)
	if err != nil {
		logrus.Errorf("Failed to initialize database with error %v", err)
		os.Exit(1)
	}
	serverpb.RegisterTrivyJavaDBServer(grpcServer, javaServer)

	grpcServer.Serve(lis)
}
