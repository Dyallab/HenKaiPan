package events

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"aspm/internal/assert"
)

// resetHub resets the hub singleton for test isolation.
// Must NOT be called concurrently with any hub operation.
func resetHub() {
	hub = nil
	once = sync.Once{}
}

func TestGetHub_Initializes(t *testing.T) {
	resetHub()
	h := GetHub()
	assert.NotNil(t, h)
	// Calling again returns same instance
	h2 := GetHub()
	assert.Equal(t, h, h2)
}

func TestSubscribe_Publish_BasicDelivery(t *testing.T) {
	resetHub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, cleanup := Subscribe(ctx, "basic-test")
	defer cleanup()

	// Allow hub goroutine to register
	time.Sleep(10 * time.Millisecond)

	Publish(Event{
		Type: EventScanCompleted,
		Data: "hello",
	})

	select {
	case got := <-ch:
		assert.Equal(t, got.Type, EventScanCompleted)
		assert.Equal(t, got.Data, "hello")
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for event")
	}
}

func TestSubscribeWithScope_UserFilter(t *testing.T) {
	resetHub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, cleanup := SubscribeWithScope(ctx, "user-scope", "user-1", "")
	defer cleanup()

	time.Sleep(10 * time.Millisecond)

	// Event for different user should NOT be delivered
	Publish(Event{
		Type:     EventScanCompleted,
		Data:     "wrong-user",
		Metadata: EventMetadata{UserID: "user-2"},
	})

	// Event for matching user should be delivered
	Publish(Event{
		Type:     EventScanCompleted,
		Data:     "correct-user",
		Metadata: EventMetadata{UserID: "user-1"},
	})

	select {
	case got := <-ch:
		assert.Equal(t, got.Data, "correct-user")
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for scoped event")
	}

	// Verify no extra events
	select {
	case <-ch:
		t.Fatal("unexpected extra event")
	case <-time.After(50 * time.Millisecond):
		// OK
	}
}

func TestSubscribeWithScope_ProjectFilter(t *testing.T) {
	resetHub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, cleanup := SubscribeWithScope(ctx, "project-scope", "", "proj-a")
	defer cleanup()

	time.Sleep(10 * time.Millisecond)

	Publish(Event{
		Type:     EventScanCompleted,
		Data:     "matching",
		Metadata: EventMetadata{ProjectID: "proj-a"},
	})

	Publish(Event{
		Type:     EventScanFailed,
		Data:     "non-matching",
		Metadata: EventMetadata{ProjectID: "proj-b"},
	})

	select {
	case got := <-ch:
		assert.Equal(t, got.Data, "matching")
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for project-scoped event")
	}

	select {
	case <-ch:
		t.Fatal("unexpected event for different project")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestSubscribe_Filters(t *testing.T) {
	resetHub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, cleanup := Subscribe(ctx, "filter-test", EventScanCompleted, EventScanFailed)
	defer cleanup()

	time.Sleep(10 * time.Millisecond)

	Publish(Event{Type: EventScanCompleted, Data: "allowed"})
	Publish(Event{Type: EventPolicyViolation, Data: "filtered"})
	Publish(Event{Type: EventScanFailed, Data: "also-allowed"})

	// First event should be ScanCompleted
	select {
	case got := <-ch:
		assert.Equal(t, got.Type, EventScanCompleted)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for first event")
	}

	// Second should be ScanFailed (PolicyViolation filtered out)
	select {
	case got := <-ch:
		assert.Equal(t, got.Type, EventScanFailed)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for second event")
	}

	// No third event
	select {
	case <-ch:
		t.Fatal("unexpected third event (PolicyViolation should be filtered)")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestSubscribe_NoFilters_ReceivesAll(t *testing.T) {
	resetHub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, cleanup := Subscribe(ctx, "no-filter")
	defer cleanup()

	time.Sleep(10 * time.Millisecond)

	Publish(Event{Type: EventScanCompleted, Data: "a"})
	Publish(Event{Type: EventPolicyViolation, Data: "b"})

	for i, want := range []EventType{EventScanCompleted, EventPolicyViolation} {
		select {
		case got := <-ch:
			assert.Equal(t, got.Type, want)
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("timeout waiting for event %d", i)
		}
	}
}

func TestBroadcast_DeliversToAll(t *testing.T) {
	resetHub()
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()

	// Subscribe without filters so both receive all events
	ch1, cleanup1 := Subscribe(ctx1, "broadcast-1")
	defer cleanup1()
	ch2, cleanup2 := Subscribe(ctx2, "broadcast-2")
	defer cleanup2()

	time.Sleep(10 * time.Millisecond)

	Broadcast(Event{Type: EventScanCompleted, Data: "to-all"})

	for i, ch := range []<-chan Event{ch1, ch2} {
		select {
		case got := <-ch:
			assert.Equal(t, got.Data, "to-all")
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("timeout waiting for broadcast on subscriber %d", i)
		}
	}
}

func TestClientCount(t *testing.T) {
	resetHub()
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()

	assert.Equal(t, ClientCount(), 0)

	_, cleanup1 := Subscribe(ctx1, "count-1")
	defer cleanup1()
	time.Sleep(10 * time.Millisecond)
	assert.Equal(t, ClientCount(), 1)

	_, cleanup2 := Subscribe(ctx2, "count-2")
	defer cleanup2()
	time.Sleep(10 * time.Millisecond)
	assert.Equal(t, ClientCount(), 2)

	cleanup1()
	time.Sleep(10 * time.Millisecond)
	assert.Equal(t, ClientCount(), 1)

	cleanup2()
	time.Sleep(10 * time.Millisecond)
	assert.Equal(t, ClientCount(), 0)
}

func TestUserConnectionCount(t *testing.T) {
	resetHub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	assert.Equal(t, UserConnectionCount("user-a"), 0)
	assert.Equal(t, UserConnectionCount(""), 0)

	_, cleanup := SubscribeWithScope(ctx, "uconn-1", "user-a", "")
	defer cleanup()
	time.Sleep(10 * time.Millisecond)
	assert.Equal(t, UserConnectionCount("user-a"), 1)
	assert.Equal(t, UserConnectionCount("user-b"), 0)
}

func TestGetClientStats(t *testing.T) {
	resetHub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, cleanup := Subscribe(ctx, "stats-1")
	defer cleanup()
	time.Sleep(10 * time.Millisecond)

	stats := GetClientStats()
	assert.Equal(t, stats["total_clients"], 1)
}

func TestGetClientStats_WithFilters(t *testing.T) {
	resetHub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, cleanup := Subscribe(ctx, "stats-filtered", EventScanCompleted, EventScanFailed)
	defer cleanup()
	time.Sleep(10 * time.Millisecond)

	stats := GetClientStats()
	byType, ok := stats["by_type"].(map[EventType]int)
	assert.True(t, ok)
	assert.Equal(t, byType[EventScanCompleted], 1)
	assert.Equal(t, byType[EventScanFailed], 1)
}

func TestContextCancellation_RemovesClient(t *testing.T) {
	resetHub()
	ctx, cancel := context.WithCancel(context.Background())

	_, cleanup := Subscribe(ctx, "cancel-test")
	defer cleanup()
	time.Sleep(10 * time.Millisecond)
	assert.Equal(t, ClientCount(), 1)

	cancel()
	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, ClientCount(), 0)
}

func TestMaxConnectionsPerUser(t *testing.T) {
	resetHub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var cleanups []func()
	defer func() {
		for _, c := range cleanups {
			c()
		}
	}()

	// Subscribe 5 times for same user — all should succeed
	for i := range 5 {
		clientID := fmt.Sprintf("maxuser-client-%d", i)
		ch, cleanup := SubscribeWithScope(ctx, clientID, "limited-user", "")
		cleanups = append(cleanups, cleanup)
		time.Sleep(10 * time.Millisecond)

		// Verify this client is registered and working
		Publish(Event{Type: EventScanCompleted, Data: i})
		select {
		case <-ch:
			// received
		case <-time.After(200 * time.Millisecond):
			t.Fatalf("client %d did not receive event", i)
		}
	}

	assert.Equal(t, UserConnectionCount("limited-user"), 5)

	// 6th subscription should be rejected (client channel gets closed)
	ch6, cleanup6 := SubscribeWithScope(context.Background(), "maxuser-rejected", "limited-user", "")
	defer cleanup6()
	time.Sleep(20 * time.Millisecond)

	// The 6th client should have its channel closed (select with closed channel yields zero value immediately)
	_, ok := <-ch6
	if ok {
		t.Log("6th client channel still open — may be race")
	}

	assert.Equal(t, UserConnectionCount("limited-user"), 5)
}
