// Code generated by protoc-gen-go.
// source: user/user.proto
// DO NOT EDIT!

/*
Package user is a generated protocol buffer package.

It is generated from these files:
	user/user.proto

It has these top-level messages:
	User
	RegisterRequest
	RegisterResponse
	LoginRequest
	LoginResponse
*/
package user

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import google_protobuf "github.com/golang/protobuf/ptypes/timestamp"
import synoday_type "github.com/synoday/golang/protogen/type/creds"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// ResponseStatus is response status enum.
type ResponseStatus int32

const (
	ResponseStatus_UNKNOWN                     ResponseStatus = 0
	ResponseStatus_SUCCESS                     ResponseStatus = 1
	ResponseStatus_INTERNAL_ERROR              ResponseStatus = 2
	ResponseStatus_CREDENTIAL_INVALID          ResponseStatus = 16
	ResponseStatus_CREDENTIAL_INVALID_EMAIL    ResponseStatus = 17
	ResponseStatus_CREDENTIAL_INVALID_USERNAME ResponseStatus = 18
	ResponseStatus_CREDENTIAL_INVALID_PASSWORD ResponseStatus = 19
	ResponseStatus_CREDENTIAL_NOT_VERIFIED     ResponseStatus = 20
	ResponseStatus_USER_INVALID_FIRST_NAME     ResponseStatus = 32
)

var ResponseStatus_name = map[int32]string{
	0:  "UNKNOWN",
	1:  "SUCCESS",
	2:  "INTERNAL_ERROR",
	16: "CREDENTIAL_INVALID",
	17: "CREDENTIAL_INVALID_EMAIL",
	18: "CREDENTIAL_INVALID_USERNAME",
	19: "CREDENTIAL_INVALID_PASSWORD",
	20: "CREDENTIAL_NOT_VERIFIED",
	32: "USER_INVALID_FIRST_NAME",
}
var ResponseStatus_value = map[string]int32{
	"UNKNOWN":                     0,
	"SUCCESS":                     1,
	"INTERNAL_ERROR":              2,
	"CREDENTIAL_INVALID":          16,
	"CREDENTIAL_INVALID_EMAIL":    17,
	"CREDENTIAL_INVALID_USERNAME": 18,
	"CREDENTIAL_INVALID_PASSWORD": 19,
	"CREDENTIAL_NOT_VERIFIED":     20,
	"USER_INVALID_FIRST_NAME":     32,
}

func (x ResponseStatus) String() string {
	return proto.EnumName(ResponseStatus_name, int32(x))
}
func (ResponseStatus) EnumDescriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

// User hold user information.
type User struct {
	// id is user unique identifier.
	Id string `protobuf:"bytes,1,opt,name=id" json:"id,omitempty"`
	// first_name is user first name.
	FirstName string `protobuf:"bytes,4,opt,name=first_name,json=firstName" json:"first_name,omitempty"`
	// last_name is user last name.
	LastName string `protobuf:"bytes,5,opt,name=last_name,json=lastName" json:"last_name,omitempty"`
	// created is user registration timestamp
	Created *google_protobuf.Timestamp `protobuf:"bytes,6,opt,name=created" json:"created,omitempty"`
}

func (m *User) Reset()                    { *m = User{} }
func (m *User) String() string            { return proto.CompactTextString(m) }
func (*User) ProtoMessage()               {}
func (*User) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *User) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *User) GetFirstName() string {
	if m != nil {
		return m.FirstName
	}
	return ""
}

func (m *User) GetLastName() string {
	if m != nil {
		return m.LastName
	}
	return ""
}

func (m *User) GetCreated() *google_protobuf.Timestamp {
	if m != nil {
		return m.Created
	}
	return nil
}

// RegisterRequest holds user registration information.
type RegisterRequest struct {
	// credential is user credential.
	Credential *synoday_type.Credential `protobuf:"bytes,1,opt,name=credential" json:"credential,omitempty"`
	// user is user profile information.
	User *User `protobuf:"bytes,2,opt,name=user" json:"user,omitempty"`
}

func (m *RegisterRequest) Reset()                    { *m = RegisterRequest{} }
func (m *RegisterRequest) String() string            { return proto.CompactTextString(m) }
func (*RegisterRequest) ProtoMessage()               {}
func (*RegisterRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *RegisterRequest) GetCredential() *synoday_type.Credential {
	if m != nil {
		return m.Credential
	}
	return nil
}

func (m *RegisterRequest) GetUser() *User {
	if m != nil {
		return m.User
	}
	return nil
}

// RegisterResponse holds the response of user registration.
type RegisterResponse struct {
	// status is the registration response status.
	Status ResponseStatus `protobuf:"varint,1,opt,name=status,enum=synoday.user.ResponseStatus" json:"status,omitempty"`
}

func (m *RegisterResponse) Reset()                    { *m = RegisterResponse{} }
func (m *RegisterResponse) String() string            { return proto.CompactTextString(m) }
func (*RegisterResponse) ProtoMessage()               {}
func (*RegisterResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *RegisterResponse) GetStatus() ResponseStatus {
	if m != nil {
		return m.Status
	}
	return ResponseStatus_UNKNOWN
}

// LoginRequest holds login request information.
type LoginRequest struct {
	// credential is user claimed credential.
	Credential *synoday_type.Credential `protobuf:"bytes,1,opt,name=credential" json:"credential,omitempty"`
}

func (m *LoginRequest) Reset()                    { *m = LoginRequest{} }
func (m *LoginRequest) String() string            { return proto.CompactTextString(m) }
func (*LoginRequest) ProtoMessage()               {}
func (*LoginRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *LoginRequest) GetCredential() *synoday_type.Credential {
	if m != nil {
		return m.Credential
	}
	return nil
}

// LoginResponse holds login request information.
type LoginResponse struct {
	// status is the login response status.
	Status ResponseStatus `protobuf:"varint,1,opt,name=status,enum=synoday.user.ResponseStatus" json:"status,omitempty"`
	// token is valid jwt token;
	Token string `protobuf:"bytes,2,opt,name=token" json:"token,omitempty"`
}

func (m *LoginResponse) Reset()                    { *m = LoginResponse{} }
func (m *LoginResponse) String() string            { return proto.CompactTextString(m) }
func (*LoginResponse) ProtoMessage()               {}
func (*LoginResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

func (m *LoginResponse) GetStatus() ResponseStatus {
	if m != nil {
		return m.Status
	}
	return ResponseStatus_UNKNOWN
}

func (m *LoginResponse) GetToken() string {
	if m != nil {
		return m.Token
	}
	return ""
}

func init() {
	proto.RegisterType((*User)(nil), "synoday.user.User")
	proto.RegisterType((*RegisterRequest)(nil), "synoday.user.RegisterRequest")
	proto.RegisterType((*RegisterResponse)(nil), "synoday.user.RegisterResponse")
	proto.RegisterType((*LoginRequest)(nil), "synoday.user.LoginRequest")
	proto.RegisterType((*LoginResponse)(nil), "synoday.user.LoginResponse")
	proto.RegisterEnum("synoday.user.ResponseStatus", ResponseStatus_name, ResponseStatus_value)
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for UserService service

type UserServiceClient interface {
	Register(ctx context.Context, in *RegisterRequest, opts ...grpc.CallOption) (*RegisterResponse, error)
	Login(ctx context.Context, in *LoginRequest, opts ...grpc.CallOption) (*LoginResponse, error)
}

type userServiceClient struct {
	cc *grpc.ClientConn
}

func NewUserServiceClient(cc *grpc.ClientConn) UserServiceClient {
	return &userServiceClient{cc}
}

func (c *userServiceClient) Register(ctx context.Context, in *RegisterRequest, opts ...grpc.CallOption) (*RegisterResponse, error) {
	out := new(RegisterResponse)
	err := grpc.Invoke(ctx, "/synoday.user.UserService/Register", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *userServiceClient) Login(ctx context.Context, in *LoginRequest, opts ...grpc.CallOption) (*LoginResponse, error) {
	out := new(LoginResponse)
	err := grpc.Invoke(ctx, "/synoday.user.UserService/Login", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for UserService service

type UserServiceServer interface {
	Register(context.Context, *RegisterRequest) (*RegisterResponse, error)
	Login(context.Context, *LoginRequest) (*LoginResponse, error)
}

func RegisterUserServiceServer(s *grpc.Server, srv UserServiceServer) {
	s.RegisterService(&_UserService_serviceDesc, srv)
}

func _UserService_Register_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RegisterRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UserServiceServer).Register(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/synoday.user.UserService/Register",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UserServiceServer).Register(ctx, req.(*RegisterRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _UserService_Login_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LoginRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(UserServiceServer).Login(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/synoday.user.UserService/Login",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(UserServiceServer).Login(ctx, req.(*LoginRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _UserService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "synoday.user.UserService",
	HandlerType: (*UserServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Register",
			Handler:    _UserService_Register_Handler,
		},
		{
			MethodName: "Login",
			Handler:    _UserService_Login_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "user/user.proto",
}

func init() { proto.RegisterFile("user/user.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 531 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0xa4, 0x53, 0xc1, 0x6e, 0xda, 0x40,
	0x10, 0x8d, 0x11, 0x90, 0x30, 0xa4, 0x64, 0x3b, 0x8d, 0x5a, 0xcb, 0x24, 0x0d, 0xf2, 0xa1, 0x4d,
	0x7b, 0xb0, 0x25, 0xda, 0x43, 0xaf, 0x04, 0x1c, 0xc5, 0x0a, 0x31, 0xd5, 0x1a, 0x12, 0xa9, 0x3d,
	0x58, 0x06, 0x36, 0xae, 0x55, 0xb0, 0xa9, 0x77, 0xa9, 0xc4, 0x1f, 0xf4, 0x2b, 0xfa, 0x8d, 0xfd,
	0x84, 0x6a, 0xd7, 0x38, 0x85, 0x26, 0x39, 0xe5, 0xb2, 0xd2, 0xbc, 0xf7, 0x66, 0xf6, 0xcd, 0xcc,
	0x2e, 0x1c, 0x2c, 0x39, 0xcb, 0x6c, 0x79, 0x58, 0x8b, 0x2c, 0x15, 0x29, 0xee, 0xf3, 0x55, 0x92,
	0x4e, 0xc3, 0x95, 0x25, 0x31, 0xe3, 0x24, 0x4a, 0xd3, 0x68, 0xc6, 0x6c, 0xc5, 0x8d, 0x97, 0xb7,
	0xb6, 0x88, 0xe7, 0x8c, 0x8b, 0x70, 0xbe, 0xc8, 0xe5, 0x06, 0x11, 0xab, 0x05, 0xb3, 0x27, 0x19,
	0x9b, 0xf2, 0x1c, 0x31, 0x7f, 0x69, 0x50, 0x1e, 0x71, 0x96, 0x61, 0x03, 0x4a, 0xf1, 0x54, 0xd7,
	0x5a, 0xda, 0x69, 0x8d, 0x96, 0xe2, 0x29, 0x1e, 0x03, 0xdc, 0xc6, 0x19, 0x17, 0x41, 0x12, 0xce,
	0x99, 0x5e, 0x56, 0x78, 0x4d, 0x21, 0x5e, 0x38, 0x67, 0xd8, 0x84, 0xda, 0x2c, 0x2c, 0xd8, 0x8a,
	0x62, 0xf7, 0x24, 0xa0, 0xc8, 0x8f, 0xb0, 0x3b, 0xc9, 0x58, 0x28, 0xd8, 0x54, 0xaf, 0xb6, 0xb4,
	0xd3, 0x7a, 0xdb, 0xb0, 0x72, 0x67, 0x56, 0xe1, 0xcc, 0x1a, 0x16, 0xce, 0x68, 0x21, 0x35, 0x39,
	0x1c, 0x50, 0x16, 0xc5, 0x5c, 0xb0, 0x8c, 0xb2, 0x1f, 0x4b, 0xc6, 0x05, 0x7e, 0x02, 0x90, 0x66,
	0x59, 0x22, 0xe2, 0x70, 0xa6, 0xcc, 0xd5, 0xdb, 0xba, 0x55, 0xf4, 0x2c, 0x9b, 0xb1, 0xba, 0x77,
	0x3c, 0xdd, 0xd0, 0xe2, 0x1b, 0x28, 0xcb, 0x91, 0xe8, 0x25, 0x95, 0x83, 0xd6, 0xe6, 0x9c, 0x2c,
	0xd9, 0x30, 0x55, 0xbc, 0x79, 0x01, 0xe4, 0xdf, 0xa5, 0x7c, 0x91, 0x26, 0x5c, 0xda, 0xaf, 0x72,
	0x11, 0x8a, 0x25, 0x57, 0x37, 0x36, 0xda, 0x47, 0xdb, 0xd9, 0x85, 0xce, 0x57, 0x1a, 0xba, 0xd6,
	0x9a, 0x17, 0xb0, 0xdf, 0x4f, 0xa3, 0x38, 0x79, 0xb2, 0x77, 0xf3, 0x2b, 0x3c, 0x5b, 0x57, 0x7a,
	0x8a, 0x21, 0x3c, 0x84, 0x8a, 0x48, 0xbf, 0xb3, 0x44, 0xcd, 0xa0, 0x46, 0xf3, 0xe0, 0xfd, 0x1f,
	0x0d, 0x1a, 0xdb, 0x09, 0x58, 0x87, 0xdd, 0x91, 0x77, 0xe9, 0x0d, 0x6e, 0x3c, 0xb2, 0x23, 0x03,
	0x7f, 0xd4, 0xed, 0x3a, 0xbe, 0x4f, 0x34, 0x44, 0x68, 0xb8, 0xde, 0xd0, 0xa1, 0x5e, 0xa7, 0x1f,
	0x38, 0x94, 0x0e, 0x28, 0x29, 0xe1, 0x4b, 0xc0, 0x2e, 0x75, 0x7a, 0x8e, 0x37, 0x74, 0x3b, 0xfd,
	0xc0, 0xf5, 0xae, 0x3b, 0x7d, 0xb7, 0x47, 0x08, 0x1e, 0x81, 0x7e, 0x1f, 0x0f, 0x9c, 0xab, 0x8e,
	0xdb, 0x27, 0xcf, 0xf1, 0x04, 0x9a, 0x0f, 0xb0, 0x23, 0x5f, 0xd6, 0xbe, 0x72, 0x08, 0x3e, 0x22,
	0xf8, 0xdc, 0xf1, 0xfd, 0x9b, 0x01, 0xed, 0x91, 0x17, 0xd8, 0x84, 0x57, 0x1b, 0x02, 0x6f, 0x30,
	0x0c, 0xae, 0x1d, 0xea, 0x9e, 0xbb, 0x4e, 0x8f, 0x1c, 0x4a, 0x52, 0xd6, 0xba, 0xcb, 0x3b, 0x77,
	0xa9, 0x3f, 0x0c, 0x54, 0xe9, 0x56, 0xfb, 0xb7, 0x06, 0x75, 0xb9, 0x72, 0x9f, 0x65, 0x3f, 0xe3,
	0x09, 0xc3, 0x4b, 0xd8, 0x2b, 0x76, 0x8e, 0xc7, 0xff, 0x8f, 0x72, 0xeb, 0x01, 0x1a, 0xaf, 0x1f,
	0xa3, 0xf3, 0x01, 0x9a, 0x3b, 0x78, 0x06, 0x15, 0xb5, 0x2c, 0x34, 0xb6, 0xa5, 0x9b, 0x6f, 0xc1,
	0x68, 0x3e, 0xc8, 0x15, 0x35, 0xce, 0xde, 0x7d, 0x79, 0x1b, 0xc5, 0xe2, 0xdb, 0x72, 0x6c, 0x4d,
	0xd2, 0xb9, 0xbd, 0x96, 0xda, 0x51, 0x3a, 0x0b, 0x93, 0x28, 0xff, 0xcc, 0x11, 0x4b, 0xd4, 0xb7,
	0x1f, 0x57, 0x55, 0xf8, 0xe1, 0x6f, 0x00, 0x00, 0x00, 0xff, 0xff, 0x83, 0x08, 0xe8, 0x7e, 0x0a,
	0x04, 0x00, 0x00,
}
