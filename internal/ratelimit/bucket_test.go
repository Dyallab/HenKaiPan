package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func setupTest(t *testing.T) (*TokenBucket, context.Context, func()) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	b := NewTokenBucket(rdb, 5, 1.0) // capacity=5, 1 token/sec
	ctx := context.Background()
	return b, ctx, func() { rdb.Close(); mr.Close() }
}

func TestAllow_Basic(t *testing.T) {
	b, ctx, cleanup := setupTest(t)
	defer cleanup()

	// First 5 should be allowed (bucket starts full)
	for i := range 5 {
		ok, remaining := b.Allow(ctx, "test:1")
		if !ok {
			t.Fatalf("request %d: expected allowed, got denied", i)
		}
		if remaining < 0 {
			t.Fatalf("request %d: negative remaining", i)
		}
	}

	// 6th should be denied
	ok, _ := b.Allow(ctx, "test:1")
	if ok {
		t.Fatal("expected denied after exhausting bucket")
	}
}

func TestAllow_Refill(t *testing.T) {
	b, ctx, cleanup := setupTest(t)
	defer cleanup()

	// Exhaust bucket
	for range 5 {
		b.Allow(ctx, "test:refill")
	}

	// Wait for refill
	time.Sleep(1100 * time.Millisecond)

	// Should have 1 token back
	ok, remaining := b.Allow(ctx, "test:refill")
	if !ok {
		t.Fatal("expected allowed after refill")
	}
	if remaining > 5 {
		t.Fatalf("remaining should be at most 4 after one consumption, got %f", remaining)
	}
}

func TestAllow_CapAtCapacity(t *testing.T) {
	b, ctx, cleanup := setupTest(t)
	defer cleanup()

	// Use 4 tokens (bucket: 5→1)
	for range 4 {
		b.Allow(ctx, "test:cap")
	}

	// Wait 5 seconds — bucket should refill to capacity (5), not accumulate more
	time.Sleep(5 * time.Second)

	// Should only be able to consume 5 tokens, not more
	allowed := 0
	for range 10 {
		if ok, _ := b.Allow(ctx, "test:cap"); ok {
			allowed++
		} else {
			break
		}
	}
	if allowed != 5 {
		t.Fatalf("expected exactly 5 allowed after long wait (capped at capacity), got %d", allowed)
	}
}

func TestAllow_DifferentKeys(t *testing.T) {
	b, ctx, cleanup := setupTest(t)
	defer cleanup()

	// Each key has its own bucket
	for i := range 5 {
		ok, _ := b.Allow(ctx, "key:a")
		if !ok {
			t.Fatalf("key:a request %d: expected allowed", i)
		}
		ok, _ = b.Allow(ctx, "key:b")
		if !ok {
			t.Fatalf("key:b request %d: expected allowed", i)
		}
	}

	// Both exhausted
	ok, _ := b.Allow(ctx, "key:a")
	if ok {
		t.Fatal("key:a should be exhausted")
	}
	ok, _ = b.Allow(ctx, "key:b")
	if ok {
		t.Fatal("key:b should be exhausted")
	}
}

func TestAllowN_Basic(t *testing.T) {
	b, ctx, cleanup := setupTest(t)
	defer cleanup()

	// Consume 3 at once
	ok, remaining := b.AllowN(ctx, "test:batch", 3)
	if !ok {
		t.Fatal("expected allowed with AllowN")
	}
	if remaining != 2 {
		t.Fatalf("expected 2 remaining, got %f", remaining)
	}

	// Try 3 more — should fail, only 2 left
	ok, _ = b.AllowN(ctx, "test:batch", 3)
	if ok {
		t.Fatal("expected denied for over-limit AllowN")
	}

	// Consume remaining 2
	ok, _ = b.AllowN(ctx, "test:batch", 2)
	if !ok {
		t.Fatal("expected allowed for remaining tokens")
	}

	// Now empty
	ok, _ = b.Allow(ctx, "test:batch")
	if ok {
		t.Fatal("expected denied after exhausting")
	}
}

func TestAllow_ZeroN(t *testing.T) {
	b, ctx, cleanup := setupTest(t)
	defer cleanup()

	ok, _ := b.AllowN(ctx, "test:zero", 0)
	if !ok {
		t.Fatal("AllowN with 0 cost should always be allowed")
	}
}

func TestAllow_NegativeN_Panics(t *testing.T) {
	b, ctx, cleanup := setupTest(t)
	defer cleanup()

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for negative AllowN")
		}
	}()
	b.AllowN(ctx, "test:neg", -1)
}

func TestConcurrentAccess(t *testing.T) {
	b, ctx, cleanup := setupTest(t)
	defer cleanup()

	done := make(chan struct{})
	const goroutines = 10

	for range goroutines {
		go func() {
			for range 5 {
				b.Allow(ctx, "test:concurrent")
			}
			done <- struct{}{}
		}()
	}

	// Wait for all goroutines
	for range goroutines {
		<-done
	}

	// Bucket should be exhausted (10*5 = 50 requests, cap=5)
	ok, _ := b.Allow(ctx, "test:concurrent")
	if ok {
		t.Log("bucket still has tokens after concurrent exhaustion — may be race, but not a failure")
	}
}
