// Code generated by protoc-gen-go.
// source: type/creds.proto
// DO NOT EDIT!

/*
Package creds is a generated protocol buffer package.

It is generated from these files:
	type/creds.proto

It has these top-level messages:
	Credential
*/
package creds

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// Credential holds user access information.
type Credential struct {
	// email is user unique email.
	Email string `protobuf:"bytes,1,opt,name=email" json:"email,omitempty"`
	// username is user unique username.
	Username string `protobuf:"bytes,2,opt,name=username" json:"username,omitempty"`
	// password is the secret credential.
	Password string `protobuf:"bytes,3,opt,name=password" json:"password,omitempty"`
}

func (m *Credential) Reset()                    { *m = Credential{} }
func (m *Credential) String() string            { return proto.CompactTextString(m) }
func (*Credential) ProtoMessage()               {}
func (*Credential) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *Credential) GetEmail() string {
	if m != nil {
		return m.Email
	}
	return ""
}

func (m *Credential) GetUsername() string {
	if m != nil {
		return m.Username
	}
	return ""
}

func (m *Credential) GetPassword() string {
	if m != nil {
		return m.Password
	}
	return ""
}

func init() {
	proto.RegisterType((*Credential)(nil), "synoday.type.Credential")
}

func init() { proto.RegisterFile("type/creds.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 157 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0xe2, 0x12, 0x28, 0xa9, 0x2c, 0x48,
	0xd5, 0x4f, 0x2e, 0x4a, 0x4d, 0x29, 0xd6, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0xe2, 0x29, 0xae,
	0xcc, 0xcb, 0x4f, 0x49, 0xac, 0xd4, 0x03, 0xc9, 0x28, 0x45, 0x71, 0x71, 0x39, 0x17, 0xa5, 0xa6,
	0xa4, 0xe6, 0x95, 0x64, 0x26, 0xe6, 0x08, 0x89, 0x70, 0xb1, 0xa6, 0xe6, 0x26, 0x66, 0xe6, 0x48,
	0x30, 0x2a, 0x30, 0x6a, 0x70, 0x06, 0x41, 0x38, 0x42, 0x52, 0x5c, 0x1c, 0xa5, 0xc5, 0xa9, 0x45,
	0x79, 0x89, 0xb9, 0xa9, 0x12, 0x4c, 0x60, 0x09, 0x38, 0x1f, 0x24, 0x57, 0x90, 0x58, 0x5c, 0x5c,
	0x9e, 0x5f, 0x94, 0x22, 0xc1, 0x0c, 0x91, 0x83, 0xf1, 0x9d, 0xf4, 0xa3, 0x74, 0xd3, 0x33, 0x4b,
	0x32, 0x4a, 0x93, 0xf4, 0x92, 0xf3, 0x73, 0xf5, 0xa1, 0xd6, 0xea, 0xa7, 0xe7, 0xe7, 0x24, 0xe6,
	0xa5, 0xeb, 0x83, 0x1d, 0x93, 0x9e, 0x9a, 0xa7, 0x8f, 0x70, 0x60, 0x12, 0x1b, 0x58, 0xd0, 0x18,
	0x10, 0x00, 0x00, 0xff, 0xff, 0xaa, 0xbe, 0x63, 0x49, 0xb5, 0x00, 0x00, 0x00,
}
