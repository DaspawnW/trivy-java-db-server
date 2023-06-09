// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v4.23.2
// source: trivy-java-db.proto

package serverpb

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type SelectIndexByArtifactIDAndGroupIDRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ArtifactID string `protobuf:"bytes,1,opt,name=ArtifactID,proto3" json:"ArtifactID,omitempty"`
	GroupID    string `protobuf:"bytes,2,opt,name=GroupID,proto3" json:"GroupID,omitempty"`
}

func (x *SelectIndexByArtifactIDAndGroupIDRequest) Reset() {
	*x = SelectIndexByArtifactIDAndGroupIDRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_trivy_java_db_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SelectIndexByArtifactIDAndGroupIDRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SelectIndexByArtifactIDAndGroupIDRequest) ProtoMessage() {}

func (x *SelectIndexByArtifactIDAndGroupIDRequest) ProtoReflect() protoreflect.Message {
	mi := &file_trivy_java_db_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SelectIndexByArtifactIDAndGroupIDRequest.ProtoReflect.Descriptor instead.
func (*SelectIndexByArtifactIDAndGroupIDRequest) Descriptor() ([]byte, []int) {
	return file_trivy_java_db_proto_rawDescGZIP(), []int{0}
}

func (x *SelectIndexByArtifactIDAndGroupIDRequest) GetArtifactID() string {
	if x != nil {
		return x.ArtifactID
	}
	return ""
}

func (x *SelectIndexByArtifactIDAndGroupIDRequest) GetGroupID() string {
	if x != nil {
		return x.GroupID
	}
	return ""
}

type IndexElement struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	GroupID     string `protobuf:"bytes,1,opt,name=GroupID,proto3" json:"GroupID,omitempty"`
	ArtifactID  string `protobuf:"bytes,2,opt,name=ArtifactID,proto3" json:"ArtifactID,omitempty"`
	Version     string `protobuf:"bytes,3,opt,name=Version,proto3" json:"Version,omitempty"`
	SHA1        []byte `protobuf:"bytes,4,opt,name=SHA1,proto3" json:"SHA1,omitempty"`
	ArchiveType string `protobuf:"bytes,5,opt,name=ArchiveType,proto3" json:"ArchiveType,omitempty"`
}

func (x *IndexElement) Reset() {
	*x = IndexElement{}
	if protoimpl.UnsafeEnabled {
		mi := &file_trivy_java_db_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IndexElement) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IndexElement) ProtoMessage() {}

func (x *IndexElement) ProtoReflect() protoreflect.Message {
	mi := &file_trivy_java_db_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IndexElement.ProtoReflect.Descriptor instead.
func (*IndexElement) Descriptor() ([]byte, []int) {
	return file_trivy_java_db_proto_rawDescGZIP(), []int{1}
}

func (x *IndexElement) GetGroupID() string {
	if x != nil {
		return x.GroupID
	}
	return ""
}

func (x *IndexElement) GetArtifactID() string {
	if x != nil {
		return x.ArtifactID
	}
	return ""
}

func (x *IndexElement) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *IndexElement) GetSHA1() []byte {
	if x != nil {
		return x.SHA1
	}
	return nil
}

func (x *IndexElement) GetArchiveType() string {
	if x != nil {
		return x.ArchiveType
	}
	return ""
}

type SelectIndexByArtifactIDAndGroupIDResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Index *IndexElement `protobuf:"bytes,1,opt,name=Index,proto3" json:"Index,omitempty"`
}

func (x *SelectIndexByArtifactIDAndGroupIDResponse) Reset() {
	*x = SelectIndexByArtifactIDAndGroupIDResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_trivy_java_db_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SelectIndexByArtifactIDAndGroupIDResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SelectIndexByArtifactIDAndGroupIDResponse) ProtoMessage() {}

func (x *SelectIndexByArtifactIDAndGroupIDResponse) ProtoReflect() protoreflect.Message {
	mi := &file_trivy_java_db_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SelectIndexByArtifactIDAndGroupIDResponse.ProtoReflect.Descriptor instead.
func (*SelectIndexByArtifactIDAndGroupIDResponse) Descriptor() ([]byte, []int) {
	return file_trivy_java_db_proto_rawDescGZIP(), []int{2}
}

func (x *SelectIndexByArtifactIDAndGroupIDResponse) GetIndex() *IndexElement {
	if x != nil {
		return x.Index
	}
	return nil
}

type SelectIndexBySha1Request struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SHA1 string `protobuf:"bytes,1,opt,name=SHA1,proto3" json:"SHA1,omitempty"`
}

func (x *SelectIndexBySha1Request) Reset() {
	*x = SelectIndexBySha1Request{}
	if protoimpl.UnsafeEnabled {
		mi := &file_trivy_java_db_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SelectIndexBySha1Request) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SelectIndexBySha1Request) ProtoMessage() {}

func (x *SelectIndexBySha1Request) ProtoReflect() protoreflect.Message {
	mi := &file_trivy_java_db_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SelectIndexBySha1Request.ProtoReflect.Descriptor instead.
func (*SelectIndexBySha1Request) Descriptor() ([]byte, []int) {
	return file_trivy_java_db_proto_rawDescGZIP(), []int{3}
}

func (x *SelectIndexBySha1Request) GetSHA1() string {
	if x != nil {
		return x.SHA1
	}
	return ""
}

type SelectIndexBySha1Response struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Index *IndexElement `protobuf:"bytes,1,opt,name=Index,proto3" json:"Index,omitempty"`
}

func (x *SelectIndexBySha1Response) Reset() {
	*x = SelectIndexBySha1Response{}
	if protoimpl.UnsafeEnabled {
		mi := &file_trivy_java_db_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SelectIndexBySha1Response) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SelectIndexBySha1Response) ProtoMessage() {}

func (x *SelectIndexBySha1Response) ProtoReflect() protoreflect.Message {
	mi := &file_trivy_java_db_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SelectIndexBySha1Response.ProtoReflect.Descriptor instead.
func (*SelectIndexBySha1Response) Descriptor() ([]byte, []int) {
	return file_trivy_java_db_proto_rawDescGZIP(), []int{4}
}

func (x *SelectIndexBySha1Response) GetIndex() *IndexElement {
	if x != nil {
		return x.Index
	}
	return nil
}

type SelectIndexesByArtifactIDAndFileTypeRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ArtifactID string `protobuf:"bytes,1,opt,name=ArtifactID,proto3" json:"ArtifactID,omitempty"`
	FileType   string `protobuf:"bytes,2,opt,name=FileType,proto3" json:"FileType,omitempty"`
}

func (x *SelectIndexesByArtifactIDAndFileTypeRequest) Reset() {
	*x = SelectIndexesByArtifactIDAndFileTypeRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_trivy_java_db_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SelectIndexesByArtifactIDAndFileTypeRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SelectIndexesByArtifactIDAndFileTypeRequest) ProtoMessage() {}

func (x *SelectIndexesByArtifactIDAndFileTypeRequest) ProtoReflect() protoreflect.Message {
	mi := &file_trivy_java_db_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SelectIndexesByArtifactIDAndFileTypeRequest.ProtoReflect.Descriptor instead.
func (*SelectIndexesByArtifactIDAndFileTypeRequest) Descriptor() ([]byte, []int) {
	return file_trivy_java_db_proto_rawDescGZIP(), []int{5}
}

func (x *SelectIndexesByArtifactIDAndFileTypeRequest) GetArtifactID() string {
	if x != nil {
		return x.ArtifactID
	}
	return ""
}

func (x *SelectIndexesByArtifactIDAndFileTypeRequest) GetFileType() string {
	if x != nil {
		return x.FileType
	}
	return ""
}

type SelectIndexesByArtifactIDAndFileTypeResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Index []*IndexElement `protobuf:"bytes,1,rep,name=Index,proto3" json:"Index,omitempty"`
}

func (x *SelectIndexesByArtifactIDAndFileTypeResponse) Reset() {
	*x = SelectIndexesByArtifactIDAndFileTypeResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_trivy_java_db_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SelectIndexesByArtifactIDAndFileTypeResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SelectIndexesByArtifactIDAndFileTypeResponse) ProtoMessage() {}

func (x *SelectIndexesByArtifactIDAndFileTypeResponse) ProtoReflect() protoreflect.Message {
	mi := &file_trivy_java_db_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SelectIndexesByArtifactIDAndFileTypeResponse.ProtoReflect.Descriptor instead.
func (*SelectIndexesByArtifactIDAndFileTypeResponse) Descriptor() ([]byte, []int) {
	return file_trivy_java_db_proto_rawDescGZIP(), []int{6}
}

func (x *SelectIndexesByArtifactIDAndFileTypeResponse) GetIndex() []*IndexElement {
	if x != nil {
		return x.Index
	}
	return nil
}

var File_trivy_java_db_proto protoreflect.FileDescriptor

var file_trivy_java_db_proto_rawDesc = []byte{
	0x0a, 0x13, 0x74, 0x72, 0x69, 0x76, 0x79, 0x2d, 0x6a, 0x61, 0x76, 0x61, 0x2d, 0x64, 0x62, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0b, 0x74, 0x72, 0x69, 0x76, 0x79, 0x4a, 0x61, 0x76, 0x61,
	0x44, 0x42, 0x22, 0x64, 0x0a, 0x28, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x49, 0x6e, 0x64, 0x65,
	0x78, 0x42, 0x79, 0x41, 0x72, 0x74, 0x69, 0x66, 0x61, 0x63, 0x74, 0x49, 0x44, 0x41, 0x6e, 0x64,
	0x47, 0x72, 0x6f, 0x75, 0x70, 0x49, 0x44, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1e,
	0x0a, 0x0a, 0x41, 0x72, 0x74, 0x69, 0x66, 0x61, 0x63, 0x74, 0x49, 0x44, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0a, 0x41, 0x72, 0x74, 0x69, 0x66, 0x61, 0x63, 0x74, 0x49, 0x44, 0x12, 0x18,
	0x0a, 0x07, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x49, 0x44, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x07, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x49, 0x44, 0x22, 0x98, 0x01, 0x0a, 0x0c, 0x49, 0x6e, 0x64,
	0x65, 0x78, 0x45, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x47, 0x72, 0x6f,
	0x75, 0x70, 0x49, 0x44, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x47, 0x72, 0x6f, 0x75,
	0x70, 0x49, 0x44, 0x12, 0x1e, 0x0a, 0x0a, 0x41, 0x72, 0x74, 0x69, 0x66, 0x61, 0x63, 0x74, 0x49,
	0x44, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x41, 0x72, 0x74, 0x69, 0x66, 0x61, 0x63,
	0x74, 0x49, 0x44, 0x12, 0x18, 0x0a, 0x07, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x12, 0x0a,
	0x04, 0x53, 0x48, 0x41, 0x31, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x53, 0x48, 0x41,
	0x31, 0x12, 0x20, 0x0a, 0x0b, 0x41, 0x72, 0x63, 0x68, 0x69, 0x76, 0x65, 0x54, 0x79, 0x70, 0x65,
	0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x41, 0x72, 0x63, 0x68, 0x69, 0x76, 0x65, 0x54,
	0x79, 0x70, 0x65, 0x22, 0x5c, 0x0a, 0x29, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x49, 0x6e, 0x64,
	0x65, 0x78, 0x42, 0x79, 0x41, 0x72, 0x74, 0x69, 0x66, 0x61, 0x63, 0x74, 0x49, 0x44, 0x41, 0x6e,
	0x64, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x49, 0x44, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x2f, 0x0a, 0x05, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x19, 0x2e, 0x74, 0x72, 0x69, 0x76, 0x79, 0x4a, 0x61, 0x76, 0x61, 0x44, 0x42, 0x2e, 0x49, 0x6e,
	0x64, 0x65, 0x78, 0x45, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x52, 0x05, 0x49, 0x6e, 0x64, 0x65,
	0x78, 0x22, 0x2e, 0x0a, 0x18, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x49, 0x6e, 0x64, 0x65, 0x78,
	0x42, 0x79, 0x53, 0x68, 0x61, 0x31, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a,
	0x04, 0x53, 0x48, 0x41, 0x31, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x53, 0x48, 0x41,
	0x31, 0x22, 0x4c, 0x0a, 0x19, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x49, 0x6e, 0x64, 0x65, 0x78,
	0x42, 0x79, 0x53, 0x68, 0x61, 0x31, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x2f,
	0x0a, 0x05, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e,
	0x74, 0x72, 0x69, 0x76, 0x79, 0x4a, 0x61, 0x76, 0x61, 0x44, 0x42, 0x2e, 0x49, 0x6e, 0x64, 0x65,
	0x78, 0x45, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x52, 0x05, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x22,
	0x69, 0x0a, 0x2b, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x65, 0x73,
	0x42, 0x79, 0x41, 0x72, 0x74, 0x69, 0x66, 0x61, 0x63, 0x74, 0x49, 0x44, 0x41, 0x6e, 0x64, 0x46,
	0x69, 0x6c, 0x65, 0x54, 0x79, 0x70, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1e,
	0x0a, 0x0a, 0x41, 0x72, 0x74, 0x69, 0x66, 0x61, 0x63, 0x74, 0x49, 0x44, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0a, 0x41, 0x72, 0x74, 0x69, 0x66, 0x61, 0x63, 0x74, 0x49, 0x44, 0x12, 0x1a,
	0x0a, 0x08, 0x46, 0x69, 0x6c, 0x65, 0x54, 0x79, 0x70, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x08, 0x46, 0x69, 0x6c, 0x65, 0x54, 0x79, 0x70, 0x65, 0x22, 0x5f, 0x0a, 0x2c, 0x53, 0x65,
	0x6c, 0x65, 0x63, 0x74, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x65, 0x73, 0x42, 0x79, 0x41, 0x72, 0x74,
	0x69, 0x66, 0x61, 0x63, 0x74, 0x49, 0x44, 0x41, 0x6e, 0x64, 0x46, 0x69, 0x6c, 0x65, 0x54, 0x79,
	0x70, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x2f, 0x0a, 0x05, 0x49, 0x6e,
	0x64, 0x65, 0x78, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x74, 0x72, 0x69, 0x76,
	0x79, 0x4a, 0x61, 0x76, 0x61, 0x44, 0x42, 0x2e, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x45, 0x6c, 0x65,
	0x6d, 0x65, 0x6e, 0x74, 0x52, 0x05, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x32, 0xaa, 0x03, 0x0a, 0x0b,
	0x54, 0x72, 0x69, 0x76, 0x79, 0x4a, 0x61, 0x76, 0x61, 0x44, 0x42, 0x12, 0x94, 0x01, 0x0a, 0x21,
	0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x42, 0x79, 0x41, 0x72, 0x74,
	0x69, 0x66, 0x61, 0x63, 0x74, 0x49, 0x44, 0x41, 0x6e, 0x64, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x49,
	0x44, 0x12, 0x35, 0x2e, 0x74, 0x72, 0x69, 0x76, 0x79, 0x4a, 0x61, 0x76, 0x61, 0x44, 0x42, 0x2e,
	0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x42, 0x79, 0x41, 0x72, 0x74,
	0x69, 0x66, 0x61, 0x63, 0x74, 0x49, 0x44, 0x41, 0x6e, 0x64, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x49,
	0x44, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x36, 0x2e, 0x74, 0x72, 0x69, 0x76, 0x79,
	0x4a, 0x61, 0x76, 0x61, 0x44, 0x42, 0x2e, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x49, 0x6e, 0x64,
	0x65, 0x78, 0x42, 0x79, 0x41, 0x72, 0x74, 0x69, 0x66, 0x61, 0x63, 0x74, 0x49, 0x44, 0x41, 0x6e,
	0x64, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x49, 0x44, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x22, 0x00, 0x12, 0x64, 0x0a, 0x11, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x49, 0x6e, 0x64, 0x65,
	0x78, 0x42, 0x79, 0x53, 0x68, 0x61, 0x31, 0x12, 0x25, 0x2e, 0x74, 0x72, 0x69, 0x76, 0x79, 0x4a,
	0x61, 0x76, 0x61, 0x44, 0x42, 0x2e, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x49, 0x6e, 0x64, 0x65,
	0x78, 0x42, 0x79, 0x53, 0x68, 0x61, 0x31, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x26,
	0x2e, 0x74, 0x72, 0x69, 0x76, 0x79, 0x4a, 0x61, 0x76, 0x61, 0x44, 0x42, 0x2e, 0x53, 0x65, 0x6c,
	0x65, 0x63, 0x74, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x42, 0x79, 0x53, 0x68, 0x61, 0x31, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x9d, 0x01, 0x0a, 0x24, 0x53, 0x65, 0x6c,
	0x65, 0x63, 0x74, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x65, 0x73, 0x42, 0x79, 0x41, 0x72, 0x74, 0x69,
	0x66, 0x61, 0x63, 0x74, 0x49, 0x44, 0x41, 0x6e, 0x64, 0x46, 0x69, 0x6c, 0x65, 0x54, 0x79, 0x70,
	0x65, 0x12, 0x38, 0x2e, 0x74, 0x72, 0x69, 0x76, 0x79, 0x4a, 0x61, 0x76, 0x61, 0x44, 0x42, 0x2e,
	0x53, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x65, 0x73, 0x42, 0x79, 0x41,
	0x72, 0x74, 0x69, 0x66, 0x61, 0x63, 0x74, 0x49, 0x44, 0x41, 0x6e, 0x64, 0x46, 0x69, 0x6c, 0x65,
	0x54, 0x79, 0x70, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x39, 0x2e, 0x74, 0x72,
	0x69, 0x76, 0x79, 0x4a, 0x61, 0x76, 0x61, 0x44, 0x42, 0x2e, 0x53, 0x65, 0x6c, 0x65, 0x63, 0x74,
	0x49, 0x6e, 0x64, 0x65, 0x78, 0x65, 0x73, 0x42, 0x79, 0x41, 0x72, 0x74, 0x69, 0x66, 0x61, 0x63,
	0x74, 0x49, 0x44, 0x41, 0x6e, 0x64, 0x46, 0x69, 0x6c, 0x65, 0x54, 0x79, 0x70, 0x65, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x42, 0x0e, 0x5a, 0x0c, 0x70, 0x6b, 0x67, 0x2f,
	0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x70, 0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_trivy_java_db_proto_rawDescOnce sync.Once
	file_trivy_java_db_proto_rawDescData = file_trivy_java_db_proto_rawDesc
)

func file_trivy_java_db_proto_rawDescGZIP() []byte {
	file_trivy_java_db_proto_rawDescOnce.Do(func() {
		file_trivy_java_db_proto_rawDescData = protoimpl.X.CompressGZIP(file_trivy_java_db_proto_rawDescData)
	})
	return file_trivy_java_db_proto_rawDescData
}

var file_trivy_java_db_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_trivy_java_db_proto_goTypes = []interface{}{
	(*SelectIndexByArtifactIDAndGroupIDRequest)(nil),     // 0: trivyJavaDB.SelectIndexByArtifactIDAndGroupIDRequest
	(*IndexElement)(nil),                                 // 1: trivyJavaDB.IndexElement
	(*SelectIndexByArtifactIDAndGroupIDResponse)(nil),    // 2: trivyJavaDB.SelectIndexByArtifactIDAndGroupIDResponse
	(*SelectIndexBySha1Request)(nil),                     // 3: trivyJavaDB.SelectIndexBySha1Request
	(*SelectIndexBySha1Response)(nil),                    // 4: trivyJavaDB.SelectIndexBySha1Response
	(*SelectIndexesByArtifactIDAndFileTypeRequest)(nil),  // 5: trivyJavaDB.SelectIndexesByArtifactIDAndFileTypeRequest
	(*SelectIndexesByArtifactIDAndFileTypeResponse)(nil), // 6: trivyJavaDB.SelectIndexesByArtifactIDAndFileTypeResponse
}
var file_trivy_java_db_proto_depIdxs = []int32{
	1, // 0: trivyJavaDB.SelectIndexByArtifactIDAndGroupIDResponse.Index:type_name -> trivyJavaDB.IndexElement
	1, // 1: trivyJavaDB.SelectIndexBySha1Response.Index:type_name -> trivyJavaDB.IndexElement
	1, // 2: trivyJavaDB.SelectIndexesByArtifactIDAndFileTypeResponse.Index:type_name -> trivyJavaDB.IndexElement
	0, // 3: trivyJavaDB.TrivyJavaDB.SelectIndexByArtifactIDAndGroupID:input_type -> trivyJavaDB.SelectIndexByArtifactIDAndGroupIDRequest
	3, // 4: trivyJavaDB.TrivyJavaDB.SelectIndexBySha1:input_type -> trivyJavaDB.SelectIndexBySha1Request
	5, // 5: trivyJavaDB.TrivyJavaDB.SelectIndexesByArtifactIDAndFileType:input_type -> trivyJavaDB.SelectIndexesByArtifactIDAndFileTypeRequest
	2, // 6: trivyJavaDB.TrivyJavaDB.SelectIndexByArtifactIDAndGroupID:output_type -> trivyJavaDB.SelectIndexByArtifactIDAndGroupIDResponse
	4, // 7: trivyJavaDB.TrivyJavaDB.SelectIndexBySha1:output_type -> trivyJavaDB.SelectIndexBySha1Response
	6, // 8: trivyJavaDB.TrivyJavaDB.SelectIndexesByArtifactIDAndFileType:output_type -> trivyJavaDB.SelectIndexesByArtifactIDAndFileTypeResponse
	6, // [6:9] is the sub-list for method output_type
	3, // [3:6] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_trivy_java_db_proto_init() }
func file_trivy_java_db_proto_init() {
	if File_trivy_java_db_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_trivy_java_db_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SelectIndexByArtifactIDAndGroupIDRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_trivy_java_db_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IndexElement); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_trivy_java_db_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SelectIndexByArtifactIDAndGroupIDResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_trivy_java_db_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SelectIndexBySha1Request); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_trivy_java_db_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SelectIndexBySha1Response); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_trivy_java_db_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SelectIndexesByArtifactIDAndFileTypeRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_trivy_java_db_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SelectIndexesByArtifactIDAndFileTypeResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_trivy_java_db_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_trivy_java_db_proto_goTypes,
		DependencyIndexes: file_trivy_java_db_proto_depIdxs,
		MessageInfos:      file_trivy_java_db_proto_msgTypes,
	}.Build()
	File_trivy_java_db_proto = out.File
	file_trivy_java_db_proto_rawDesc = nil
	file_trivy_java_db_proto_goTypes = nil
	file_trivy_java_db_proto_depIdxs = nil
}
