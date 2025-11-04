package database

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

var (
	rdb *redis.Client
	ctx = context.Background()
)

func InitRedisClient(addr string) {
	rdb = redis.NewClient(&redis.Options{
		Addr: addr,
		DB:   0,
	})
}

func UpdateClientBalance(nodeID int32, clientID string, balance int32) error {
	key := fmt.Sprintf("node:%d", nodeID)
	return rdb.HSet(ctx, key, clientID, balance).Err()
}

func GetClientBalance(nodeID int32, clientID string) (int32, error) {
	key := fmt.Sprintf("node:%d", nodeID)
	val, err := rdb.HGet(ctx, key, clientID).Int()
	return int32(val), err
}

func GetAllClientBalances(nodeID int32) (map[string]int32, error) {
	key := fmt.Sprintf("node:%d", nodeID)
	res := make(map[string]int32)
	vals, err := rdb.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, err
	}
	for k, v := range vals {
		var intval int
		fmt.Sscanf(v, "%d", &intval)
		res[k] = int32(intval)
	}
	return res, nil
}
