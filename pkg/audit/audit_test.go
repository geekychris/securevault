package audit

import (
	"bufio"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestFileLogger(t *testing.T) (*FileLogger, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	l, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("NewFileLogger: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l, path
}

func countLines(t *testing.T, path string) int {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	n := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if len(scanner.Bytes()) > 0 {
			n++
		}
	}
	return n
}

func TestFileLogger_RecordShape(t *testing.T) {
	tests := []struct {
		name    string
		event   Event
		success bool
	}{
		{
			name: "secret_read_success",
			event: Event{
				Type:       EventSecretRead,
				Path:       "secret/foo",
				TokenID:    "s.abcdefghijklmnop",
				RemoteAddr: "127.0.0.1:1234",
				Success:    true,
			},
			success: true,
		},
		{
			name: "secret_read_failure",
			event: Event{
				Type:       EventSecretRead,
				Path:       "secret/foo",
				TokenID:    "s.abcdefghijklmnop",
				RemoteAddr: "127.0.0.1:1234",
				Success:    false,
				Error:      "not found",
			},
			success: false,
		},
		{
			name: "secret_write_success",
			event: Event{
				Type:       EventSecretWrite,
				Path:       "secret/bar",
				TokenID:    "s.abcdefghijklmnop",
				RemoteAddr: "127.0.0.1:1234",
				Success:    true,
			},
			success: true,
		},
		{
			name: "secret_write_failure",
			event: Event{
				Type:       EventSecretWrite,
				Path:       "secret/bar",
				TokenID:    "s.abcdefghijklmnop",
				RemoteAddr: "127.0.0.1:1234",
				Success:    false,
				Error:      "storage error",
			},
			success: false,
		},
		{
			name: "secret_delete_success",
			event: Event{
				Type:       EventSecretDelete,
				Path:       "secret/baz",
				TokenID:    "s.abcdefghijklmnop",
				RemoteAddr: "127.0.0.1:1234",
				Success:    true,
			},
			success: true,
		},
		{
			name: "secret_delete_failure",
			event: Event{
				Type:       EventSecretDelete,
				Path:       "secret/baz",
				TokenID:    "s.abcdefghijklmnop",
				RemoteAddr: "127.0.0.1:1234",
				Success:    false,
				Error:      "permission denied",
			},
			success: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l, path := newTestFileLogger(t)

			if err := l.Log(tc.event); err != nil {
				t.Fatalf("Log: %v", err)
			}

			if got := countLines(t, path); got != 1 {
				t.Fatalf("expected 1 line written, got %d", got)
			}

			events, err := l.Query(QueryFilter{Limit: 10})
			if err != nil {
				t.Fatalf("Query: %v", err)
			}
			if len(events) != 1 {
				t.Fatalf("expected 1 event from Query, got %d", len(events))
			}

			got := events[0]
			if got.Type != tc.event.Type {
				t.Errorf("Type = %q, want %q", got.Type, tc.event.Type)
			}
			if got.Path != tc.event.Path {
				t.Errorf("Path = %q, want %q", got.Path, tc.event.Path)
			}
			if got.Success != tc.success {
				t.Errorf("Success = %v, want %v", got.Success, tc.success)
			}
			if got.Error != tc.event.Error {
				t.Errorf("Error = %q, want %q", got.Error, tc.event.Error)
			}
			if got.Timestamp.IsZero() {
				t.Error("Timestamp was not auto-populated")
			}
			wantTokenID := tc.event.TokenID[:6] + "..."
			if got.TokenID != wantTokenID {
				t.Errorf("TokenID = %q, want masked %q", got.TokenID, wantTokenID)
			}
		})
	}
}

func TestFileLogger_TimestampPreservedWhenSet(t *testing.T) {
	l, _ := newTestFileLogger(t)

	ts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := l.Log(Event{Type: EventSecretRead, Path: "p", Timestamp: ts, Success: true}); err != nil {
		t.Fatalf("Log: %v", err)
	}

	events, err := l.Query(QueryFilter{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if !events[0].Timestamp.Equal(ts) {
		t.Errorf("Timestamp = %v, want %v (should not be overwritten)", events[0].Timestamp, ts)
	}
}

func TestFileLogger_AppendOnly(t *testing.T) {
	l, path := newTestFileLogger(t)

	const n = 25
	for i := 0; i < n; i++ {
		if err := l.Log(Event{Type: EventSecretRead, Path: "secret/x", Success: true}); err != nil {
			t.Fatalf("Log #%d: %v", i, err)
		}
	}

	if got := countLines(t, path); got != n {
		t.Fatalf("expected %d lines on disk, got %d", n, got)
	}

	events, err := l.Query(QueryFilter{Limit: n})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(events) != n {
		t.Fatalf("expected %d events from Query, got %d", n, len(events))
	}

	// Re-opening the file must see every previously appended record -- no
	// earlier record is ever overwritten or removed by a later Log call.
	l2, err := NewFileLogger(path)
	if err != nil {
		t.Fatalf("NewFileLogger (reopen): %v", err)
	}
	defer l2.Close()

	reloaded, err := l2.Query(QueryFilter{Limit: n})
	if err != nil {
		t.Fatalf("Query (reopen): %v", err)
	}
	if len(reloaded) != n {
		t.Fatalf("expected %d events after reopening the log, got %d", n, len(reloaded))
	}
}

func TestNopLogger(t *testing.T) {
	n := &NopLogger{}

	if err := n.Log(Event{Type: EventSecretRead, Success: false, Error: "whatever"}); err != nil {
		t.Errorf("Log() = %v, want nil", err)
	}

	events, err := n.Query(QueryFilter{})
	if err != nil {
		t.Errorf("Query() err = %v, want nil", err)
	}
	if events == nil {
		t.Error("Query() returned nil slice, want non-nil empty slice")
	}
	if len(events) != 0 {
		t.Errorf("Query() = %d events, want 0", len(events))
	}

	if err := n.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
}
