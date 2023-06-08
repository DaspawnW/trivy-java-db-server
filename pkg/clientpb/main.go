package clientpb

import (
	"context"
	"github.com/aquasecurity/trivy-java-db/pkg/types"
	"github.com/daspawnw/trivy-java-db-server/pkg/serverpb"
	"github.com/daspawnw/trivy-java-db-server/pkg/utils"
	"google.golang.org/grpc"
)

type JavaDBClient struct {
	client     serverpb.TrivyJavaDBClient
	connection *grpc.ClientConn
}

func NewJavaDBClient(addr string, opts []grpc.DialOption) (*JavaDBClient, error) {
	conn, err := grpc.Dial(addr, opts...)
	if err != nil {
		return nil, err
	}

	c := serverpb.NewTrivyJavaDBClient(conn)

	return &JavaDBClient{
		client:     c,
		connection: conn,
	}, nil
}

func (c *JavaDBClient) Close() {
	if c.connection != nil {
		c.connection.Close()
	}
}

func (c *JavaDBClient) SelectIndexByArtifactIDAndGroupID(artifactID, groupID string) (types.Index, error) {
	req := &serverpb.SelectIndexByArtifactIDAndGroupIDRequest{
		ArtifactID: artifactID,
		GroupID:    groupID,
	}

	resp, err := c.client.SelectIndexByArtifactIDAndGroupID(context.Background(), req)
	var index types.Index
	if err != nil {
		return index, err
	}

	return utils.MapIndexElementToIndex(resp.Index), nil
}

func (c *JavaDBClient) SelectIndexBySha1(sha1 string) (types.Index, error) {
	req := &serverpb.SelectIndexBySha1Request{SHA1: sha1}

	resp, err := c.client.SelectIndexBySha1(context.Background(), req)
	var index types.Index
	if err != nil {
		return index, err
	}

	return utils.MapIndexElementToIndex(resp.Index), nil
}

func (c *JavaDBClient) SelectIndexesByArtifactIDAndFileType(artifactID string, fileType types.ArchiveType) ([]types.Index, error) {
	req := &serverpb.SelectIndexesByArtifactIDAndFileTypeRequest{ArtifactID: artifactID, FileType: utils.ArchiveTypeToString(fileType)}

	resp, err := c.client.SelectIndexesByArtifactIDAndFileType(context.Background(), req)
	var indexes []types.Index
	if err != nil {
		return indexes, err
	}

	for _, index := range resp.Index {
		indexes = append(indexes, utils.MapIndexElementToIndex(index))
	}

	return indexes, nil
}
