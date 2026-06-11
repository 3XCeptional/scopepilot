package queue

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
)

// Task represents a step in the distributed hunt system.
type Task struct {
	ID           string    `json:"id"`
	Target       string    `json:"target"`
	Type         string    `json:"type"`         // recon|vuln|payload|analyze
	Priority     int       `json:"priority"`     // 1-5
	Status       string    `json:"status"`       // pending|running|done|failed|blocked
	Dependencies []string  `json:"dependencies"` // Task IDs that this task depends on
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Error        string    `json:"error,omitempty"`
}

// Queue manages persistent tasks via a JSON-lines file.
type Queue struct {
	path           string
	mu             sync.Mutex
	scopeValidator func(string) bool
}

// NewQueue creates a new task queue at the specified path.
func NewQueue(path string, scopeValidator func(string) bool) *Queue {
	return &Queue{
		path:           path,
		scopeValidator: scopeValidator,
	}
}

// Add validates the task's target, sets default values, and appends it to the queue.
func (q *Queue) Add(task *Task) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	unlock, err := q.lock()
	if err != nil {
		return err
	}
	defer unlock()

	// 1. Validate Target using scopeValidator
	if q.scopeValidator != nil && !q.scopeValidator(task.Target) {
		return fmt.Errorf("target %q is out of scope", task.Target)
	}

	// 2. Validate Type
	switch task.Type {
	case "recon", "vuln", "payload", "analyze":
		// valid
	default:
		return fmt.Errorf("invalid task type %q", task.Type)
	}

	// 3. Validate Priority
	if task.Priority < 1 || task.Priority > 5 {
		return fmt.Errorf("invalid priority %d (must be 1-5)", task.Priority)
	}

	// Initialize ID if empty
	if task.ID == "" {
		task.ID = uuid.New().String()
	}

	// Initialize Status if empty
	if task.Status == "" {
		task.Status = "pending"
	}

	now := time.Now()
	task.CreatedAt = now
	task.UpdatedAt = now

	// Load existing tasks
	tasks, err := q.loadTasks()
	if err != nil {
		return err
	}

	// Check for duplicate ID
	for _, t := range tasks {
		if t.ID == task.ID {
			return fmt.Errorf("task with ID %q already exists", task.ID)
		}
	}

	// Append new task
	tasks = append(tasks, *task)

	// Save back to file
	return q.saveTasks(tasks)
}

// List retrieves all tasks, optionally filtering by status.
func (q *Queue) List(status string) ([]Task, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	unlock, err := q.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	tasks, err := q.loadTasks()
	if err != nil {
		return nil, err
	}

	if status == "" {
		return tasks, nil
	}

	var filtered []Task
	for _, t := range tasks {
		if t.Status == status {
			filtered = append(filtered, t)
		}
	}
	return filtered, nil
}

// Get retrieves a task by its ID.
func (q *Queue) Get(id string) (*Task, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	unlock, err := q.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	tasks, err := q.loadTasks()
	if err != nil {
		return nil, err
	}

	for _, t := range tasks {
		if t.ID == id {
			return &t, nil
		}
	}

	return nil, fmt.Errorf("task with ID %s not found", id)
}

// Next selects the highest priority pending task, marks it running, and returns it.
func (q *Queue) Next() (*Task, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	unlock, err := q.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	tasks, err := q.loadTasks()
	if err != nil {
		return nil, err
	}

	bestIdx := -1
	for i, t := range tasks {
		if t.Status != "pending" {
			continue
		}
		if bestIdx == -1 {
			bestIdx = i
			continue
		}
		// Pick highest priority first (5 is highest, 1 is lowest).
		// Tie-break by CreatedAt (earlier task first).
		if t.Priority > tasks[bestIdx].Priority {
			bestIdx = i
		} else if t.Priority == tasks[bestIdx].Priority {
			if t.CreatedAt.Before(tasks[bestIdx].CreatedAt) {
				bestIdx = i
			}
		}
	}

	if bestIdx == -1 {
		return nil, nil // No pending tasks
	}

	// Mark the selected task as running
	tasks[bestIdx].Status = "running"
	tasks[bestIdx].UpdatedAt = time.Now()

	err = q.saveTasks(tasks)
	if err != nil {
		return nil, err
	}

	return &tasks[bestIdx], nil
}

// Start updates a task's status to "running".
func (q *Queue) Start(id string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	unlock, err := q.lock()
	if err != nil {
		return err
	}
	defer unlock()

	tasks, err := q.loadTasks()
	if err != nil {
		return err
	}

	found := false
	for i, t := range tasks {
		if t.ID == id {
			tasks[i].Status = "running"
			tasks[i].UpdatedAt = time.Now()
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("task with ID %s not found", id)
	}

	return q.saveTasks(tasks)
}

// Complete updates a task's status to "done".
func (q *Queue) Complete(id string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	unlock, err := q.lock()
	if err != nil {
		return err
	}
	defer unlock()

	tasks, err := q.loadTasks()
	if err != nil {
		return err
	}

	found := false
	for i, t := range tasks {
		if t.ID == id {
			tasks[i].Status = "done"
			tasks[i].UpdatedAt = time.Now()
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("task with ID %s not found", id)
	}

	return q.saveTasks(tasks)
}

// Fail updates a task's status to "failed" and records the error message.
func (q *Queue) Fail(id string, taskErr error) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	unlock, err := q.lock()
	if err != nil {
		return err
	}
	defer unlock()

	tasks, err := q.loadTasks()
	if err != nil {
		return err
	}

	found := false
	for i, t := range tasks {
		if t.ID == id {
			tasks[i].Status = "failed"
			if taskErr != nil {
				tasks[i].Error = taskErr.Error()
			}
			tasks[i].UpdatedAt = time.Now()
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("task with ID %s not found", id)
	}

	return q.saveTasks(tasks)
}

// Retry updates a task's status back to "pending" and clears any error message.
func (q *Queue) Retry(id string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	unlock, err := q.lock()
	if err != nil {
		return err
	}
	defer unlock()

	tasks, err := q.loadTasks()
	if err != nil {
		return err
	}

	found := false
	for i, t := range tasks {
		if t.ID == id {
			tasks[i].Status = "pending"
			tasks[i].Error = ""
			tasks[i].UpdatedAt = time.Now()
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("task with ID %s not found", id)
	}

	return q.saveTasks(tasks)
}

// loadTasks reads all tasks from the JSON-lines file.
// It returns an empty list without error if the file doesn't exist.
func (q *Queue) loadTasks() ([]Task, error) {
	file, err := os.Open(q.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to open queue file: %w", err)
	}
	defer file.Close()

	var tasks []Task
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var t Task
		if err := json.Unmarshal([]byte(line), &t); err != nil {
			return nil, fmt.Errorf("failed to unmarshal task: %w", err)
		}
		tasks = append(tasks, t)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading queue file: %w", err)
	}

	return tasks, nil
}

// saveTasks writes the list of tasks back to the JSON-lines file atomically.
func (q *Queue) saveTasks(tasks []Task) error {
	dir := filepath.Dir(q.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create queue directory: %w", err)
	}

	tmpFile, err := os.CreateTemp(dir, "queue-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer func() {
		tmpFile.Close()
		os.Remove(tmpFile.Name()) // Clean up if rename wasn't successful
	}()

	for _, t := range tasks {
		data, err := json.Marshal(t)
		if err != nil {
			return fmt.Errorf("failed to marshal task: %w", err)
		}
		if _, err := tmpFile.Write(append(data, '\n')); err != nil {
			return fmt.Errorf("failed to write to temp file: %w", err)
		}
	}

	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	if err := os.Rename(tmpFile.Name(), q.path); err != nil {
		return fmt.Errorf("failed to rename temp file to queue path: %w", err)
	}

	return nil
}

// lock acquires an exclusive advisory lock on q.path + ".lock".
// It returns a function that, when called, releases the lock and closes the lock file.
func (q *Queue) lock() (func(), error) {
	dir := filepath.Dir(q.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create queue directory: %w", err)
	}

	lockPath := q.path + ".lock"
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		return nil, fmt.Errorf("failed to open lock file: %w", err)
	}

	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to acquire file lock: %w", err)
	}

	unlock := func() {
		syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		file.Close()
	}
	return unlock, nil
}
