package pagination

import (
	"net/url"
	"strconv"
)

const (
	DefaultLimit = 50
	MaxLimit     = 100
)

// Params holds parsed pagination state: page number, items per page, and the
// computed SQL OFFSET value.
type Params struct {
	Page   int
	Limit  int
	Offset int
}

// FromQuery extracts page and limit from URL query parameters and applies
// sensible defaults (page≥1, 1≤limit≤MaxLimit).
func FromQuery(q url.Values) Params {
	page, _ := strconv.Atoi(q.Get("page"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	return Normalize(page, limit, DefaultLimit, MaxLimit)
}

// FromQueryWithDefaults is like FromQuery but allows custom default and
// maximum limit values (useful for endpoints that need different limits).
func FromQueryWithDefaults(q url.Values, defaultLimit, maxLimit int) Params {
	page, _ := strconv.Atoi(q.Get("page"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	return Normalize(page, limit, defaultLimit, maxLimit)
}

// Normalize coerces raw page/limit into valid values. Pages below 1 are
// clamped to 1; limits outside [1, maxLimit] fall back to defaultLimit.
func Normalize(page, limit, defaultLimit, maxLimit int) Params {
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > maxLimit {
		limit = defaultLimit
	}
	return Params{
		Page:   page,
		Limit:  limit,
		Offset: (page - 1) * limit,
	}
}