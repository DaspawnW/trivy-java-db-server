package utils

import (
	"github.com/aquasecurity/trivy-java-db/pkg/types"
	"github.com/daspawnw/trivy-java-db-server/pkg/serverpb"
)

func MapIndexToIndexElement(idx types.Index) *serverpb.IndexElement {
	return &serverpb.IndexElement{
		GroupID:     idx.GroupID,
		ArtifactID:  idx.ArtifactID,
		SHA1:        idx.SHA1,
		Version:     idx.Version,
		ArchiveType: ArchiveTypeToString(idx.ArchiveType),
	}
}

func MapIndexElementToIndex(idx *serverpb.IndexElement) types.Index {
	return types.Index{
		GroupID:     idx.GroupID,
		ArtifactID:  idx.ArtifactID,
		SHA1:        idx.SHA1,
		Version:     idx.Version,
		ArchiveType: StringToArchiveType(idx.ArchiveType),
	}
}

func StringToArchiveType(str string) types.ArchiveType {
	switch str {
	case types.JarType:
		return types.JarType
	case types.AarType:
		return types.AarType
	case types.IndexesDir:
		return types.IndexesDir
	}

	return ""
}

func ArchiveTypeToString(archiveType types.ArchiveType) string {
	switch archiveType {
	case types.AarType:
		return types.AarType
	case types.JarType:
		return types.JarType
	case types.IndexesDir:
		return types.IndexesDir
	}
	return ""
}
