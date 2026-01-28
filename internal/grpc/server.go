package grpc

import (
	"context"
	"net"

	"ads-httpproxy/internal/config"
	"ads-httpproxy/internal/visibility"
	"ads-httpproxy/pkg/logging"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// Server is the gRPC Admin Server
type Server struct {
	cfg        *config.Config
	grpcServer *grpc.Server
	// TODO: Embed unimplemented service server here once generated
}

func NewServer(cfg *config.Config) *Server {
	s := grpc.NewServer()
	// Register reflection for debugging
	reflection.Register(s)

	// TODO: Register actual services (StatsService, ConfigService)
	// pb.RegisterAdminServer(s, &adminImpl{})

	return &Server{
		cfg:        cfg,
		grpcServer: s,
	}
}

func (s *Server) Start(addr string) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		logging.Logger.Error("Failed to listen for gRPC", zap.Error(err))
		return
	}

	logging.Logger.Info("Starting gRPC Admin Server", zap.String("addr", addr))
	go func() {
		if err := s.grpcServer.Serve(lis); err != nil {
			logging.Logger.Error("gRPC Server failed", zap.Error(err))
		}
	}()
}

func (s *Server) Stop() {
	s.grpcServer.GracefulStop()
}

// adminImpl will implement the generated interface later
type adminImpl struct {
	// UnimplementedAdminServer
}

func (s *adminImpl) GetStats(ctx context.Context, req *struct{}) (*struct{}, error) {
	// Placeholder
	_ = visibility.GetStats()
	return &struct{}{}, nil
}
