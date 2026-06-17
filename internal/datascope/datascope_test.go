package datascope

import (
	"aspm/internal/assert"
	"testing"
)

func TestAdminNoFilter(t *testing.T) {
	s := Admin()
	assert.Nil(t, s.UserID)
}

func TestForUserHasUserID(t *testing.T) {
	s := ForUser("usr_001")
	assert.NotNil(t, s.UserID)
	assert.Equal(t, *s.UserID, "usr_001")
}

func TestAdminAndForUserAreDistinct(t *testing.T) {
	a := Admin()
	u := ForUser("usr_001")
	assert.NotEqual(t, a.UserID, u.UserID)
}
