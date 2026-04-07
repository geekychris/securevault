package audit

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// EventType represents the type of audit event
type EventType string

const (
	EventSecretRead     EventType = "secret.read"
	EventSecretWrite    EventType = "secret.write"
	EventSecretDelete   EventType = "secret.delete"
	EventSecretList     EventType = "secret.list"
	EventSecretMetadata EventType = "secret.metadata"

	EventTokenCreate EventType = "token.create"
	EventTokenRenew  EventType = "token.renew"
	EventTokenRevoke EventType = "token.revoke"
	EventTokenLookup EventType = "token.lookup"

	EventPolicyCreate EventType = "policy.create"
	EventPolicyUpdate EventType = "policy.update"
	EventPolicyDelete EventType = "policy.delete"
	EventPolicyRead   EventType = "policy.read"
	EventPolicyList   EventType = "policy.list"

	EventSeal   EventType = "sys.seal"
	EventUnseal EventType = "sys.unseal"
	EventInit   EventType = "sys.init"

	EventAuthFailed EventType = "auth.failed"

	EventReplicationSync EventType = "replication.sync"
)

// Event represents an audit log entry
type Event struct {
	Timestamp  time.Time              `json:"timestamp"`
	Type       EventType              `json:"type"`
	Path       string                 `json:"path,omitempty"`
	TokenID    string                 `json:"token_id,omitempty"`
	PolicyIDs  []string               `json:"policy_ids,omitempty"`
	RemoteAddr string                 `json:"remote_addr"`
	Success    bool                   `json:"success"`
	Error      string                 `json:"error,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// Logger is the audit logger interface
type Logger interface {
	Log(event Event) error
	Query(filter QueryFilter) ([]Event, error)
	Close() error
}

// QueryFilter for querying audit logs
type QueryFilter struct {
	StartTime *time.Time `json:"start_time,omitempty"`
	EndTime   *time.Time `json:"end_time,omitempty"`
	Type      EventType  `json:"type,omitempty"`
	Path      string     `json:"path,omitempty"`
	TokenID   string     `json:"token_id,omitempty"`
	Limit     int        `json:"limit,omitempty"`
	Offset    int        `json:"offset,omitempty"`
}

// FileLogger writes audit events to a file
type FileLogger struct {
	mu       sync.Mutex
	file     *os.File
	filepath string
	events   []Event // in-memory buffer for queries (bounded)
	maxMem   int     // max events to keep in memory for queries
}

// NewFileLogger creates a new file-based audit logger
func NewFileLogger(filepath string) (*FileLogger, error) {
	if err := os.MkdirAll(filepath[:len(filepath)-len("/audit.log")], 0700); err != nil {
		// Try using the filepath directly
	}

	f, err := os.OpenFile(filepath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log file: %w", err)
	}

	logger := &FileLogger{
		file:     f,
		filepath: filepath,
		events:   make([]Event, 0, 10000),
		maxMem:   10000,
	}

	// Load existing events for query support
	logger.loadExistingEvents()

	return logger, nil
}

// loadExistingEvents loads events from the file for query support
func (l *FileLogger) loadExistingEvents() {
	data, err := os.ReadFile(l.filepath)
	if err != nil || len(data) == 0 {
		return
	}

	// Parse line-delimited JSON
	lines := splitLines(data)
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		var event Event
		if err := json.Unmarshal(line, &event); err == nil {
			l.events = append(l.events, event)
		}
	}

	// Keep only the last maxMem events
	if len(l.events) > l.maxMem {
		l.events = l.events[len(l.events)-l.maxMem:]
	}
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			if i > start {
				lines = append(lines, data[start:i])
			}
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}

// Log writes an audit event
func (l *FileLogger) Log(event Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Mask the token ID for security - only show prefix
	if len(event.TokenID) > 6 {
		event.TokenID = event.TokenID[:6] + "..."
	}

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal audit event: %w", err)
	}

	if _, err := l.file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("failed to write audit event: %w", err)
	}

	// Sync to disk for durability
	if err := l.file.Sync(); err != nil {
		log.Printf("WARNING: failed to sync audit log: %v", err)
	}

	// Add to in-memory buffer
	l.events = append(l.events, event)
	if len(l.events) > l.maxMem {
		l.events = l.events[1:]
	}

	return nil
}

// Query returns audit events matching the filter
func (l *FileLogger) Query(filter QueryFilter) ([]Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var results []Event
	for _, event := range l.events {
		if filter.StartTime != nil && event.Timestamp.Before(*filter.StartTime) {
			continue
		}
		if filter.EndTime != nil && event.Timestamp.After(*filter.EndTime) {
			continue
		}
		if filter.Type != "" && event.Type != filter.Type {
			continue
		}
		if filter.Path != "" && event.Path != filter.Path {
			continue
		}
		if filter.TokenID != "" && event.TokenID != filter.TokenID {
			continue
		}
		results = append(results, event)
	}

	// Apply offset
	if filter.Offset > 0 && filter.Offset < len(results) {
		results = results[filter.Offset:]
	} else if filter.Offset >= len(results) {
		return []Event{}, nil
	}

	// Apply limit
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > len(results) {
		limit = len(results)
	}

	return results[:limit], nil
}

// Close closes the audit logger
func (l *FileLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Close()
}

// NopLogger is a no-op audit logger for testing
type NopLogger struct{}

func (n *NopLogger) Log(event Event) error                     { return nil }
func (n *NopLogger) Query(filter QueryFilter) ([]Event, error) { return []Event{}, nil }
func (n *NopLogger) Close() error                              { return nil }
