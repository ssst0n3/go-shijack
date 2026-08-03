package gohijack

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestHijackRejectsEmptyPayloadFile exposes #11: a payload file that exists but
// is empty must be rejected up front instead of silently injecting an empty
// segment (the operator sees "hijack succeeded" while the victim gets nothing).
func TestHijackRejectsEmptyPayloadFile(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty")
	assert.NoError(t, os.WriteFile(empty, nil, 0644))

	err := Hijack("lo", "127.0.0.1", 80, empty, true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

// TestHijackRejectsMissingPayloadFile ensures the missing-file path still
// returns an error (regression guard for the new empty-check added below it).
func TestHijackRejectsMissingPayloadFile(t *testing.T) {
	err := Hijack("lo", "127.0.0.1", 80, "/nonexistent/path/flag", true)
	assert.Error(t, err)
}
