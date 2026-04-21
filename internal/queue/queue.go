package queue

import "github.com/hibiken/asynq"

func NewClient(addr string) *asynq.Client {
	return asynq.NewClient(asynq.RedisClientOpt{Addr: addr})
}

func NewServer(addr string, concurrency int) *asynq.Server {
	return asynq.NewServer(
		asynq.RedisClientOpt{Addr: addr},
		asynq.Config{Concurrency: concurrency},
	)
}
