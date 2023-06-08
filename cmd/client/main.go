package main

import (
	"encoding/hex"
	"github.com/aquasecurity/trivy-java-db/pkg/types"
	"github.com/daspawnw/trivy-java-db-server/pkg/clientpb"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"os"
)

func main() {
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))

	client, err := clientpb.NewJavaDBClient("localhost:50051", opts)
	if err != nil {
		logrus.Errorf("Failed to create javadbclient with error %v", err)
		os.Exit(1)
	}
	defer client.Close()

	resp, err := client.SelectIndexByArtifactIDAndGroupID("wiremock", "com.github.tomakehurst")
	if err != nil {
		logrus.Errorf("Failed to SelectIndexByArtifactIDAndGroupID with error %v", err)
	} else {
		logrus.Infof("Response for SelectIndexByArtifactIDAndGroupID %v", resp)
	}

	byShaResp, err := client.SelectIndexBySha1(hex.EncodeToString(resp.SHA1))
	if err != nil {
		logrus.Errorf("Failed to SelectIndexBySha1 with error %v", err)
	} else {
		logrus.Infof("Response for SelectIndexBySha1 %v", byShaResp)
	}

	byArtifactIDAndFileTypeResp, err := client.SelectIndexesByArtifactIDAndFileType(resp.ArtifactID, types.JarType)
	if err != nil {
		logrus.Errorf("Failed to SelectIndexesByArtifactIDAndFileType with error %v", err)
	} else {
		logrus.Infof("Response for SelectIndexesByArtifactIDAndFileType %v", byArtifactIDAndFileTypeResp)
	}

}
