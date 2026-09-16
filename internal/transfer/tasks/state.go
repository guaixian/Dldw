// Package tasks implements the cache task lifecycle (spec 4.3):
//
//	queued -> downloading -> downloaded -> uploading -> registering -> ready
//	                            \-> failed(retryable) -> dead
package tasks

import "fmt"

// Status is a task lifecycle state.
type Status string

const (
	StatusQueued      Status = "queued"
	StatusDownloading Status = "downloading"
	StatusDownloaded  Status = "downloaded"
	StatusUploading   Status = "uploading"
	StatusRegistering Status = "registering"
	StatusReady       Status = "ready"
	StatusFailed      Status = "failed"
	StatusDead        Status = "dead"
)

// Terminal reports whether no further transitions occur from s.
func (s Status) Terminal() bool { return s == StatusReady || s == StatusDead }

// transitions lists allowed edges of the state machine.
var transitions = map[Status][]Status{
	StatusQueued:      {StatusDownloading},
	StatusDownloading: {StatusDownloaded, StatusFailed},
	StatusDownloaded:  {StatusUploading, StatusFailed},
	StatusUploading:   {StatusRegistering, StatusFailed},
	StatusRegistering: {StatusReady, StatusFailed},
	StatusFailed:      {StatusDownloading, StatusDead}, // retry or give up
	StatusReady:       {},
	StatusDead:        {},
}

// Can reports whether s -> next is a legal transition.
func (s Status) Can(next Status) bool {
	for _, n := range transitions[s] {
		if n == next {
			return true
		}
	}
	return false
}

// ValidateTransition returns an error when s -> next is illegal.
func ValidateTransition(from, to Status) error {
	if from.Can(to) {
		return nil
	}
	return fmt.Errorf("tasks: illegal transition %s -> %s", from, to)
}
