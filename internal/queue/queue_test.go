package queue

import (
	"testing"

	"github.com/hibiken/asynq"

	"aspm/internal/assert"
)

func TestNewClient_ReturnsClient(t *testing.T) {
	c := NewClient("localhost:6379")
	assert.NotNil(t, c)
	_, ok := interface{}(c).(*asynq.Client)
	assert.True(t, ok)
}

func TestNewClient_EmptyAddr(t *testing.T) {
	c := NewClient("")
	assert.NotNil(t, c)
}

func TestNewServer_ReturnsServer(t *testing.T) {
	s := NewServer("localhost:6379", 10)
	assert.NotNil(t, s)
	_, ok := interface{}(s).(*asynq.Server)
	assert.True(t, ok)
}

func TestNewServer_ConcurrencyOne(t *testing.T) {
	s := NewServer("localhost:6379", 1)
	assert.NotNil(t, s)
}

func TestNewServer_HighConcurrency(t *testing.T) {
	s := NewServer("localhost:6379", 100)
	assert.NotNil(t, s)
}
