package node

import (
	pb "pbft-bank-application/pbft-bank-application/proto"
)

func convertAttacksFromProto(attacks []*pb.Attack) []*Attack {
	if len(attacks) == 0 {
		return nil
	}
	out := make([]*Attack, 0, len(attacks))
	for _, a := range attacks {
		out = append(out, &Attack{
			Name:  a.Name,
			Nodes: a.Nodes,
		})
	}
	return out
}

func isValidStateToIncludeInViewChange(status Status) bool {
	if status == StatusPrepared || status == StatusCommitted || status == StatusExecuted {
		return true
	}
	return false
}

func (s *Node) HasAttack(name string) (bool, []int32) {
	if !s.IsMalicious {
		return false, nil
	}
	if len(s.Attacks) == 0 {
		return false, nil
	}
	for _, a := range s.Attacks {
		if a != nil && a.Name == name {
			return true, a.Nodes
		}
	}
	return false, nil
}
