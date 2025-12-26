// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025 Jeremy Hahn
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build integration

package api

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jeremyhahn/go-frostdkg/pkg/transport"
)

// TestRunner executes a sequence of TestActions with support for
// concurrent participant operations and timeout handling.
type TestRunner struct {
	actions        []TestAction
	timeout        time.Duration
	errorCollector *ErrorCollector
}

// NewTestRunner creates a new test runner with the specified timeout.
func NewTestRunner(timeout time.Duration) *TestRunner {
	if timeout == 0 {
		timeout = 5 * time.Minute // Default 5 minute timeout
	}

	return &TestRunner{
		actions:        make([]TestAction, 0),
		timeout:        timeout,
		errorCollector: NewErrorCollector(),
	}
}

// AddAction adds a test action to the sequence.
func (r *TestRunner) AddAction(action TestAction) {
	r.actions = append(r.actions, action)
}

// AddActions adds multiple test actions to the sequence.
func (r *TestRunner) AddActions(actions ...TestAction) {
	r.actions = append(r.actions, actions...)
}

// Run executes all actions in sequence and returns any errors.
func (r *TestRunner) Run(ctx context.Context) error {
	// Create a context with timeout
	runCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	for i, action := range r.actions {
		select {
		case <-runCtx.Done():
			return fmt.Errorf("test timeout after action %d (%s): %w", i, action.Name(), runCtx.Err())
		default:
		}

		if err := action.Execute(runCtx); err != nil {
			return fmt.Errorf("action %d (%s) failed: %w", i, action.Name(), err)
		}
	}

	return nil
}

// RunParallel executes multiple actions concurrently.
// All actions must complete successfully, or an error is returned.
func (r *TestRunner) RunParallel(ctx context.Context, actions ...TestAction) error {
	if len(actions) == 0 {
		return nil
	}

	runCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	var wg sync.WaitGroup
	errors := make(chan error, len(actions))

	for _, action := range actions {
		wg.Add(1)
		go func(a TestAction) {
			defer wg.Done()

			if err := a.Execute(runCtx); err != nil {
				errors <- fmt.Errorf("%s failed: %w", a.Name(), err)
			}
		}(action)
	}

	// Wait for all actions to complete
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All actions completed
		close(errors)

		// Check for errors
		var errs []error
		for err := range errors {
			errs = append(errs, err)
		}

		if len(errs) > 0 {
			return fmt.Errorf("parallel execution failed with %d errors: %v", len(errs), errs)
		}

		return nil

	case <-runCtx.Done():
		return fmt.Errorf("parallel execution timeout: %w", runCtx.Err())
	}
}

// GetErrors returns all collected errors.
func (r *TestRunner) GetErrors() []error {
	return r.errorCollector.GetErrors()
}

// Clear resets the runner's action sequence.
func (r *TestRunner) Clear() {
	r.actions = r.actions[:0]
	r.errorCollector.Clear()
}

// ErrorCollector collects errors from concurrent operations.
type ErrorCollector struct {
	errors []error
	mu     sync.Mutex
}

// NewErrorCollector creates a new error collector.
func NewErrorCollector() *ErrorCollector {
	return &ErrorCollector{
		errors: make([]error, 0),
	}
}

// Add adds an error to the collection.
func (ec *ErrorCollector) Add(err error) {
	if err == nil {
		return
	}

	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.errors = append(ec.errors, err)
}

// GetErrors returns all collected errors.
func (ec *ErrorCollector) GetErrors() []error {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	result := make([]error, len(ec.errors))
	copy(result, ec.errors)
	return result
}

// HasErrors returns true if any errors have been collected.
func (ec *ErrorCollector) HasErrors() bool {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	return len(ec.errors) > 0
}

// Clear removes all collected errors.
func (ec *ErrorCollector) Clear() {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.errors = ec.errors[:0]
}

// Count returns the number of collected errors.
func (ec *ErrorCollector) Count() int {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	return len(ec.errors)
}

// ConcurrentDKGRunner manages concurrent DKG execution for multiple participants.
type ConcurrentDKGRunner struct {
	results []*DKGResultWithError
	timeout time.Duration
	mu      sync.Mutex
}

// DKGResultWithError pairs a DKG result with its error.
type DKGResultWithError struct {
	Result *transport.DKGResult
	Error  error
	Index  int
}

// NewConcurrentDKGRunner creates a new concurrent DKG runner.
func NewConcurrentDKGRunner(timeout time.Duration) *ConcurrentDKGRunner {
	if timeout == 0 {
		timeout = 5 * time.Minute
	}

	return &ConcurrentDKGRunner{
		results: make([]*DKGResultWithError, 0),
		timeout: timeout,
	}
}

// RunParticipants runs DKG for multiple participants concurrently.
func (r *ConcurrentDKGRunner) RunParticipants(
	ctx context.Context,
	participants []transport.Participant,
	params []*transport.DKGParams,
) ([]*transport.DKGResult, error) {
	if len(participants) != len(params) {
		return nil, fmt.Errorf("participants and params length mismatch: %d != %d", len(participants), len(params))
	}

	runCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	var wg sync.WaitGroup
	results := make([]*DKGResultWithError, len(participants))

	for i := range participants {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			result, err := participants[idx].RunDKG(runCtx, params[idx])
			results[idx] = &DKGResultWithError{
				Result: result,
				Error:  err,
				Index:  idx,
			}
		}(i)
	}

	// Wait for all to complete
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Check for errors
		var errs []error
		successResults := make([]*transport.DKGResult, 0, len(participants))

		for _, res := range results {
			if res.Error != nil {
				errs = append(errs, fmt.Errorf("participant %d: %w", res.Index, res.Error))
			} else if res.Result != nil {
				successResults = append(successResults, res.Result)
			}
		}

		if len(errs) > 0 {
			return nil, fmt.Errorf("DKG failed for %d participants: %v", len(errs), errs)
		}

		r.mu.Lock()
		r.results = results
		r.mu.Unlock()

		return successResults, nil

	case <-runCtx.Done():
		return nil, fmt.Errorf("DKG execution timeout: %w", runCtx.Err())
	}
}

// GetResults returns all DKG results (including errors).
func (r *ConcurrentDKGRunner) GetResults() []*DKGResultWithError {
	r.mu.Lock()
	defer r.mu.Unlock()

	results := make([]*DKGResultWithError, len(r.results))
	copy(results, r.results)
	return results
}
