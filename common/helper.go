package common

func IsNodePresentInAttackNodes(attackNodes []int32, nodeID int32) bool {
	for _, t := range attackNodes {
		if t == nodeID {
			return true
		}
	}
	return false
}
