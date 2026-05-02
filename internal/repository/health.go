package repository

import (
	"context"
	"time"

	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5/pgxpool"
)

type healthRepo struct {
	db    *pgxpool.Pool
	redis *asynq.RedisClientOpt
}

func NewHealthRepo(db *pgxpool.Pool, redisAddr string) *healthRepo {
	return &healthRepo{
		db: db,
		redis: &asynq.RedisClientOpt{
			Addr: redisAddr,
		},
	}
}

func (r *healthRepo) CheckDB(ctx context.Context) error {
	return r.db.Ping(ctx)
}

func (r *healthRepo) CheckRedis(ctx context.Context) error {
	client := asynq.NewClient(*r.redis)
	defer client.Close()
	
	inspector := asynq.NewInspector(*r.redis)
	defer inspector.Close()
	
	_, err := inspector.Queues()
	return err
}

func (r *healthRepo) CheckWorker(ctx context.Context) (bool, error) {
	inspector := asynq.NewInspector(*r.redis)
	defer inspector.Close()

	queues, err := inspector.Queues()
	if err != nil {
		return false, err
	}

	for _, queue := range queues {
		stats, err := inspector.GetQueueInfo(queue)
		if err != nil {
			continue
		}

		if stats.Processed > 0 && !stats.Timestamp.IsZero() {
			if time.Since(stats.Timestamp) < 5*time.Minute {
				return true, nil
			}
		}
	}

	return false, nil
}
