package client

import (
	"context"
	"fmt"
	"net"

	pb "pbft-bank-application/pbft-bank-application/proto"

	"google.golang.org/grpc"
)

type CallbackServer struct {
	pb.UnimplementedClientCallbackServer
	Hub *Hub
}

func NewCallbackServer(h *Hub) *CallbackServer { return &CallbackServer{Hub: h} }

func (s *CallbackServer) Start(listenAddr string) error {
	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listenAddr, err)
	}
	gs := grpc.NewServer()
	pb.RegisterClientCallbackServer(gs, s)
	return gs.Serve(lis)
}

func (s *CallbackServer) ReplyToClientFromNode(ctx context.Context, r *pb.ReplyToClientRequest) (*pb.Ack, error) {
	//log.Printf("[CallbackServer] Received reply from replica=%d | view=%d | time=%d | result=%t",
	//	r.ReplicaId, r.View, r.Time, r.Result)
	s.Hub.ProcessNodeReply(r)
	return &pb.Ack{Success: true, Message: "ok"}, nil
}
