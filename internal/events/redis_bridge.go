package events

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

const redisChannel = "aspm:events"

var bridge *redisBridge

type redisBridge struct {
	client    *redis.Client
	enabled  bool
	started  atomic.Bool
}

// InitRedisBridge initializes the Redis pub/sub bridge for cross-process event delivery.
// If addr is empty, the bridge is disabled (in-memory only, useful for tests).
func InitRedisBridge(addr string) {
	if addr == "" {
		slog.Debug("SSE Redis bridge disabled: no Redis address")
		return
	}

	client := redis.NewClient(&redis.Options{
		Addr: addr,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		slog.Error("SSE Redis bridge: failed to connect", "addr", addr, "err", err)
		return
	}

	bridge = &redisBridge{
		client:   client,
		enabled: true,
	}

	slog.Info("SSE Redis bridge initialized", "addr", addr)
}

// PublishToRedis publishes an event to the Redis channel so other processes
// (e.g., the API server) can deliver it to their SSE clients.
func PublishToRedis(event Event) {
	if bridge == nil || !bridge.enabled {
		return
	}

	data, err := json.Marshal(event)
	if err != nil {
		slog.Warn("SSE Redis bridge: failed to marshal event", "err", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := bridge.client.Publish(ctx, redisChannel, data).Err(); err != nil {
		slog.Warn("SSE Redis bridge: failed to publish event", "err", err)
	}
}

// SubscribeFromRedis starts a goroutine that listens for events on the Redis channel
// and dispatches them to the local SSE hub. Call this in processes that serve SSE clients
// (i.e., the API server).
func SubscribeFromRedis() {
	if bridge == nil || !bridge.enabled {
		slog.Debug("SSE Redis bridge: not subscribing, bridge not enabled")
		return
	}

	if !bridge.started.CompareAndSwap(false, true) {
		return
	}

	go func() {
		for {
			sub := bridge.client.Subscribe(context.Background(), redisChannel)
			_, err := sub.Receive(context.Background())
			if err != nil {
				slog.Error("SSE Redis bridge: subscribe failed, retrying in 5s", "err", err)
				sub.Close()
				time.Sleep(5 * time.Second)
				continue
			}

			slog.Info("SSE Redis bridge: subscribed to Redis channel", "channel", redisChannel)

			ch := sub.Channel()
			for msg := range ch {
				var event Event
				if err := json.Unmarshal([]byte(msg.Payload), &event); err != nil {
					slog.Warn("SSE Redis bridge: failed to unmarshal event", "err", err)
					continue
				}

				GetHub().events <- event
			}

			sub.Close()
			slog.Warn("SSE Redis bridge: subscription channel closed, reconnecting in 5s")
			time.Sleep(5 * time.Second)
		}
	}()
}