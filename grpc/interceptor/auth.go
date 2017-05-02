package interceptor

import (
	"strings"

	"golang.org/x/net/context"

	"github.com/knq/jwt"
	"github.com/synoday/golang/auth"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

// Credential holds user confidential access information.
type Credential struct {
	Email    string `json:"email"`
	Password string `json:"passworf"`
}

// AuthUnary is grpc interceptor that responsible to handle authentication,
// by parsing the token field from metadata.
func AuthUnary() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		var err error

		md, ok := metadata.FromContext(ctx)
		if !ok {
			return nil, grpc.Errorf(codes.DataLoss, "auth unary interceptor: failed to get metadata")
		}

		var userID string
		if token, ok := md["authorization"]; ok {
			val := strings.Fields(token[0])
			if len(val) != 2 {
				return nil, grpc.Errorf(codes.Unauthenticated, "invalid token format")
			}
			userID, err = jwt.PeekPayloadField([]byte(val[1]), "uid")
			if err != nil {
				return nil, grpc.Errorf(codes.Unauthenticated, "failed to get user ID")
			}
			newCtx := context.WithValue(ctx, auth.UserIDKey, userID)
			return handler(newCtx, req)
		}
		return nil, grpc.Errorf(codes.Unauthenticated, "authentication required")
	}
}
