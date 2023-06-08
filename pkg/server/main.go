package server

import (
	"context"
	"fmt"
	trivydb "github.com/aquasecurity/trivy-java-db/pkg/db"
	"github.com/daspawnw/trivy-java-db-server/pkg/serverpb"
	"github.com/daspawnw/trivy-java-db-server/pkg/utils"
	"github.com/sirupsen/logrus"
)

type TrivyJavaDBServer struct {
	serverpb.UnimplementedTrivyJavaDBServer

	driver trivydb.DB
}

func (t *TrivyJavaDBServer) SelectIndexByArtifactIDAndGroupID(ctx context.Context, req *serverpb.SelectIndexByArtifactIDAndGroupIDRequest) (*serverpb.SelectIndexByArtifactIDAndGroupIDResponse, error) {
	logrus.Debugf("Received SelectIndexByArtifactIDAndGroupID(%s, %s) request", req.ArtifactID, req.GroupID)

	idx, err := t.driver.SelectIndexByArtifactIDAndGroupID(req.ArtifactID, req.GroupID)
	if err != nil {
		logrus.Errorf("SelectIndexByArtifactIDAndGroupID(%s, %s) failed with error %v", req.ArtifactID, req.GroupID, err)
		return &serverpb.SelectIndexByArtifactIDAndGroupIDResponse{Index: nil}, err
	}

	index := utils.MapIndexToIndexElement(idx)
	return &serverpb.SelectIndexByArtifactIDAndGroupIDResponse{Index: index}, nil
}

func (t *TrivyJavaDBServer) SelectIndexBySha1(ctx context.Context, req *serverpb.SelectIndexBySha1Request) (*serverpb.SelectIndexBySha1Response, error) {
	logrus.Debugf("Received SelectIndexBySha1(%s) request", req.SHA1)

	idx, err := t.driver.SelectIndexBySha1(req.SHA1)
	if err != nil {
		logrus.Errorf("SelectIndexBySha1(%s) failed with error %v", req.SHA1, err)
		return &serverpb.SelectIndexBySha1Response{Index: nil}, err
	}

	index := utils.MapIndexToIndexElement(idx)
	return &serverpb.SelectIndexBySha1Response{Index: index}, nil
}
func (t *TrivyJavaDBServer) SelectIndexesByArtifactIDAndFileType(ctx context.Context, req *serverpb.SelectIndexesByArtifactIDAndFileTypeRequest) (*serverpb.SelectIndexesByArtifactIDAndFileTypeResponse, error) {
	archiveType := utils.StringToArchiveType(req.FileType)
	logrus.Debugf("Received SelectIndexesByArtifactIDAndFileType(%s, %s) request", req.ArtifactID, archiveType)

	idxList, err := t.driver.SelectIndexesByArtifactIDAndFileType(req.ArtifactID, archiveType)
	if err != nil {
		logrus.Errorf("SelectIndexesByArtifactIDAndFileType(%s, %s) failed with error %v", req.ArtifactID, archiveType, err)
		return &serverpb.SelectIndexesByArtifactIDAndFileTypeResponse{Index: nil}, err
	}

	var indexList []*serverpb.IndexElement
	for _, idx := range idxList {
		indexList = append(indexList, utils.MapIndexToIndexElement(idx))
	}

	return &serverpb.SelectIndexesByArtifactIDAndFileTypeResponse{Index: indexList}, nil
}

func NewTrivyJavaDBServer(dbDir string) (*TrivyJavaDBServer, error) {
	dbc, err := trivydb.New(dbDir)
	if err != nil {
		return nil, fmt.Errorf("Java DB open error: %v", err)
	}

	return &TrivyJavaDBServer{
		driver: dbc,
	}, nil
}
