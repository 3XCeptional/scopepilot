package queue

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestQueue(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "queue-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	queuePath := filepath.Join(tmpDir, "tasks.jsonl")

	// Scope validator: targets containing "good.com" or "in-scope.com" are allowed
	scopeValidator := func(target string) bool {
		return target == "in-scope.com" || target == "good.com"
	}

	q := NewQueue(queuePath, scopeValidator)

	// 1. Test out-of-scope reject
	badTask := &Task{
		Target:   "bad.com",
		Type:     "recon",
		Priority: 3,
	}
	err = q.Add(badTask)
	if err == nil {
		t.Fatalf("expected error for out-of-scope target, got nil")
	}

	// 2. Test valid add
	goodTask := &Task{
		Target:   "good.com",
		Type:     "recon",
		Priority: 3,
	}
	err = q.Add(goodTask)
	if err != nil {
		t.Fatalf("failed to add valid task: %v", err)
	}
	if goodTask.ID == "" {
		t.Errorf("expected generated UUID, got empty ID")
	}
	if goodTask.Status != "pending" {
		t.Errorf("expected status 'pending', got %q", goodTask.Status)
	}

	// 3. Test list
	tasks, err := q.List("")
	if err != nil {
		t.Fatalf("failed to list tasks: %v", err)
	}
	if len(tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(tasks))
	}
	if tasks[0].ID != goodTask.ID {
		t.Errorf("task ID mismatch: got %q, want %q", tasks[0].ID, goodTask.ID)
	}

	// 4. Test priority ordering in Next()
	// Add three more tasks with different priorities:
	// task1: Priority 2 (created first)
	// task2: Priority 5 (created second)
	// task3: Priority 5 (created third)
	// Next() should return task2 first (highest priority, earlier created than task3).
	// Then task3, then task0 (priority 3), then task1 (priority 2).
	task1 := &Task{Target: "good.com", Type: "vuln", Priority: 2}
	task2 := &Task{Target: "good.com", Type: "payload", Priority: 5}
	// Wait a tiny bit to ensure clear timestamp difference
	time.Sleep(10 * time.Millisecond)
	task3 := &Task{Target: "good.com", Type: "analyze", Priority: 5}

	if err := q.Add(task1); err != nil {
		t.Fatalf("failed to add task1: %v", err)
	}
	if err := q.Add(task2); err != nil {
		t.Fatalf("failed to add task2: %v", err)
	}
	if err := q.Add(task3); err != nil {
		t.Fatalf("failed to add task3: %v", err)
	}

	// Next should be task2 (priority 5, older than task3)
	n, err := q.Next()
	if err != nil {
		t.Fatalf("Next failed: %v", err)
	}
	if n == nil || n.ID != task2.ID {
		t.Fatalf("expected Next to return task2 (%s), got %+v", task2.ID, n)
	}
	if n.Status != "running" {
		t.Errorf("expected returned task status to be 'running', got %q", n.Status)
	}

	// Next should be task3 (priority 5)
	n, err = q.Next()
	if err != nil {
		t.Fatalf("Next failed: %v", err)
	}
	if n == nil || n.ID != task3.ID {
		t.Fatalf("expected Next to return task3, got %+v", n)
	}

	// Next should be goodTask (priority 3)
	n, err = q.Next()
	if err != nil {
		t.Fatalf("Next failed: %v", err)
	}
	if n == nil || n.ID != goodTask.ID {
		t.Fatalf("expected Next to return goodTask, got %+v", n)
	}

	// Next should be task1 (priority 2)
	n, err = q.Next()
	if err != nil {
		t.Fatalf("Next failed: %v", err)
	}
	if n == nil || n.ID != task1.ID {
		t.Fatalf("expected Next to return task1, got %+v", n)
	}

	// Next should be nil now
	n, err = q.Next()
	if err != nil {
		t.Fatalf("Next failed: %v", err)
	}
	if n != nil {
		t.Fatalf("expected Next to return nil, got %+v", n)
	}

	// 5. Test lifecycle (Complete / Fail)
	// Complete task2
	err = q.Complete(task2.ID)
	if err != nil {
		t.Fatalf("failed to complete task2: %v", err)
	}
	// Fail task3
	err = q.Fail(task3.ID, errors.New("something went wrong"))
	if err != nil {
		t.Fatalf("failed to fail task3: %v", err)
	}

	// Retrieve task lists and check statuses
	completedTasks, err := q.List("done")
	if err != nil {
		t.Fatalf("failed to list completed: %v", err)
	}
	if len(completedTasks) != 1 || completedTasks[0].ID != task2.ID {
		t.Errorf("expected 1 completed task (task2), got: %+v", completedTasks)
	}

	failedTasks, err := q.List("failed")
	if err != nil {
		t.Fatalf("failed to list failed: %v", err)
	}
	if len(failedTasks) != 1 || failedTasks[0].ID != task3.ID {
		t.Errorf("expected 1 failed task (task3), got: %+v", failedTasks)
	}
	if failedTasks[0].Error != "something went wrong" {
		t.Errorf("expected error message 'something went wrong', got %q", failedTasks[0].Error)
	}

	// 6. Test retry
	err = q.Retry(task3.ID)
	if err != nil {
		t.Fatalf("failed to retry task3: %v", err)
	}
	retriedTasks, err := q.List("pending")
	if err != nil {
		t.Fatalf("failed to list pending: %v", err)
	}
	found := false
	for _, pt := range retriedTasks {
		if pt.ID == task3.ID {
			found = true
			if pt.Error != "" {
				t.Errorf("expected error message to be cleared, got %q", pt.Error)
			}
			break
		}
	}
	if !found {
		t.Errorf("expected task3 to be in pending status after retry")
	}

	// 7. Test persistence
	// Instantiate a new queue object referencing the same file path.
	q2 := NewQueue(queuePath, scopeValidator)
	persistedTasks, err := q2.List("")
	if err != nil {
		t.Fatalf("failed to load persisted tasks: %v", err)
	}
	if len(persistedTasks) != 4 {
		t.Fatalf("expected 4 persisted tasks, got %d", len(persistedTasks))
	}
}

func TestQueueStartAndGet(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "queue-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	queuePath := filepath.Join(tmpDir, "tasks.jsonl")
	q := NewQueue(queuePath, nil)

	task := &Task{
		Target:   "example.com",
		Type:     "recon",
		Priority: 3,
	}
	if err := q.Add(task); err != nil {
		t.Fatalf("failed to add task: %v", err)
	}

	// Test Get
	got, err := q.Get(task.ID)
	if err != nil {
		t.Fatalf("failed to get task: %v", err)
	}
	if got.ID != task.ID || got.Status != "pending" {
		t.Errorf("unexpected task: %+v", got)
	}

	// Test Start
	if err := q.Start(task.ID); err != nil {
		t.Fatalf("failed to start task: %v", err)
	}

	got, err = q.Get(task.ID)
	if err != nil {
		t.Fatalf("failed to get task after start: %v", err)
	}
	if got.Status != "running" {
		t.Errorf("expected status 'running', got %q", got.Status)
	}

	// Test Get invalid ID
	_, err = q.Get("invalid-id")
	if err == nil {
		t.Error("expected error getting invalid ID, got nil")
	}

	// Test Start invalid ID
	err = q.Start("invalid-id")
	if err == nil {
		t.Error("expected error starting invalid ID, got nil")
	}
}

func TestQueueDuplicateID(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "queue-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	queuePath := filepath.Join(tmpDir, "tasks.jsonl")
	q := NewQueue(queuePath, nil)

	task1 := &Task{
		ID:       "duplicate-id",
		Target:   "example.com",
		Type:     "recon",
		Priority: 3,
	}
	if err := q.Add(task1); err != nil {
		t.Fatalf("failed to add task1: %v", err)
	}

	task2 := &Task{
		ID:       "duplicate-id",
		Target:   "example.com",
		Type:     "recon",
		Priority: 3,
	}
	err = q.Add(task2)
	if err == nil {
		t.Error("expected error adding task with duplicate ID, got nil")
	}
}

func TestStaleLockIsRemoved(t *testing.T) {
	tmpDir := t.TempDir()
	queuePath := filepath.Join(tmpDir, "stale-test.jsonl")
	lockPath := queuePath + ".lock"

	// Create a stale lock file (older than 30s).
	if err := os.WriteFile(lockPath, []byte("stale"), 0644); err != nil {
		t.Fatalf("write stale lock: %v", err)
	}
	// Set mtime to 60 seconds ago.
	past := time.Now().Add(-60 * time.Second)
	if err := os.Chtimes(lockPath, past, past); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	// Acquire should succeed: stale lock is removed.
	unlock, err := newLockFile(queuePath)
	if err != nil {
		t.Fatalf("expected stale lock to be cleared, got: %v", err)
	}
	unlock() // release

	// Lock file should be gone.
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Error("expected lock file to be removed after unlock")
	}
}

func TestRecentLockIsNotRemoved(t *testing.T) {
	tmpDir := t.TempDir()
	queuePath := filepath.Join(tmpDir, "recent-test.jsonl")
	lockPath := queuePath + ".lock"

	// Create a recent lock file (<30s old).
	if err := os.WriteFile(lockPath, []byte("fresh"), 0644); err != nil {
		t.Fatalf("write fresh lock: %v", err)
	}

	// Acquire should fail: lock is recent.
	_, err := newLockFile(queuePath)
	if err == nil {
		t.Error("expected error for recent lock file, got nil")
	}

	// Lock file should still exist.
	if _, err := os.Stat(lockPath); os.IsNotExist(err) {
		t.Error("expected lock file to still exist after failed acquire")
	}
}
