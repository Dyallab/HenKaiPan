package events

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"aspm/internal/assert"
)

func resetBridgeForTest() {
	bridge = nil
}

func resetHubForTest() {
	hub = nil
	once = sync.Once{}
}

func setupRedisWithClient(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close(); mr.Close() })
	return mr, rdb
}

func TestInitRedisBridge_EmptyAddr_Disabled(t *testing.T) {
	resetBridgeForTest()
	InitRedisBridge("")
	assert.Nil(t, bridge)
}

func TestInitRedisBridge_ValidAddr_Enabled(t *testing.T) {
	resetBridgeForTest()
	mr, _ := setupRedisWithClient(t)
	InitRedisBridge(mr.Addr())
	assert.NotNil(t, bridge)
	assert.True(t, bridge.enabled)
}

func TestPublishToRedis_BridgeNil_NoOp(t *testing.T) {
	resetBridgeForTest()
	bridge = nil
	PublishToRedis(Event{Type: EventScanCompleted, Data: "test"})
}

func TestPublishToRedis_BridgeDisabled_NoOp(t *testing.T) {
	resetBridgeForTest()
	bridge = &redisBridge{enabled: false}
	PublishToRedis(Event{Type: EventScanCompleted, Data: "test"})
}

func TestPublishToRedis_PublishesToChannel(t *testing.T) {
	resetBridgeForTest()
	mr, rdb := setupRedisWithClient(t)

	InitRedisBridge(mr.Addr())

	sub := rdb.Subscribe(context.Background(), redisChannel)
	defer sub.Close()

	_, err := sub.Receive(context.Background())
	assert.Nil(t, err)

	ch := sub.Channel()

	PublishToRedis(Event{
		Type: EventScanCompleted,
		Data: "payload-1",
		Metadata: EventMetadata{
			UserID: "u-1",
		},
	})

	select {
	case msg := <-ch:
		assert.MatchesRegexp(t, msg.Payload, "scan_completed")
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for Redis message")
	}
}

func TestPublishToRedis_RoundtripJSON(t *testing.T) {
	resetBridgeForTest()
	mr, rdb := setupRedisWithClient(t)

	InitRedisBridge(mr.Addr())

	sub := rdb.Subscribe(context.Background(), redisChannel)
	defer sub.Close()
	_, err := sub.Receive(context.Background())
	assert.Nil(t, err)
	pubsubCh := sub.Channel()

	event := Event{
		Type: EventScanFailed,
		Data: ScanData{ScanID: "s-99", ProjectID: "p-1", Error: "timeout"},
		Metadata: EventMetadata{
			ProjectID: "p-1",
		},
	}
	PublishToRedis(event)

	select {
	case msg := <-pubsubCh:
		var decoded Event
		err := json.Unmarshal([]byte(msg.Payload), &decoded)
		assert.Nil(t, err)
		assert.Equal(t, decoded.Type, EventScanFailed)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for Redis message")
	}
}

func TestSubscribeFromRedis_BridgeDisabled_NoOp(t *testing.T) {
	resetBridgeForTest()
	bridge = &redisBridge{enabled: false}
	SubscribeFromRedis()
	assert.False(t, bridge.started.Load())
}

func TestSubscribeFromRedis_BridgeNil_NoOp(t *testing.T) {
	resetBridgeForTest()
	bridge = nil
	SubscribeFromRedis()
}

func TestSubscribeFromRedis_SingleStartGuard(t *testing.T) {
	resetBridgeForTest()
	mr, _ := setupRedisWithClient(t)
	InitRedisBridge(mr.Addr())

	SubscribeFromRedis()
	assert.True(t, bridge.started.Load())

	SubscribeFromRedis()
	assert.True(t, bridge.started.Load())
}
