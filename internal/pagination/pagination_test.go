package pagination

import (
	"net/url"
	"testing"

	"aspm/internal/assert"
)

func TestNormalize_ClampsPage(t *testing.T) {
	tests := []struct {
		name  string
		page  int
		limit int
		want  Params
	}{
		{"negative page", -1, 10, Params{Page: 1, Limit: 10, Offset: 0}},
		{"zero page", 0, 10, Params{Page: 1, Limit: 10, Offset: 0}},
		{"valid page", 3, 10, Params{Page: 3, Limit: 10, Offset: 20}},
		{"page 1", 1, 10, Params{Page: 1, Limit: 10, Offset: 0}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Normalize(tc.page, tc.limit, 20, 100)
			assert.Equal(t, got, tc.want)
		})
	}
}

func TestNormalize_ClampsLimit(t *testing.T) {
	tests := []struct {
		name        string
		limit       int
		defaultLmt  int
		maxLmt      int
		wantLimit   int
	}{
		{"zero limit", 0, 20, 100, 20},
		{"negative limit", -5, 20, 100, 20},
		{"exceeds max", 200, 20, 100, 20},
		{"at max", 100, 20, 100, 100},
		{"valid within range", 50, 20, 100, 50},
		{"at minimum 1", 1, 20, 100, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Normalize(1, tc.limit, tc.defaultLmt, tc.maxLmt)
			assert.Equal(t, got.Limit, tc.wantLimit)
		})
	}
}

func TestNormalize_OffsetCalculated(t *testing.T) {
	got := Normalize(3, 20, 20, 100)
	assert.Equal(t, got.Offset, (3-1)*20)
}

func TestFromQuery_ParsesParams(t *testing.T) {
	q := url.Values{"page": {"2"}, "limit": {"30"}}
	got := FromQuery(q)
	assert.Equal(t, got.Page, 2)
	assert.Equal(t, got.Limit, 30)
}

func TestFromQuery_Defaults(t *testing.T) {
	q := url.Values{}
	got := FromQuery(q)
	assert.Equal(t, got.Page, 1)
	assert.Equal(t, got.Limit, DefaultLimit)
}
