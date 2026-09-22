// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"fmt"
)

// UpdateLLMBudget atomically reads and replaces the LLM-owned budget document.
// The callback must not perform I/O or reenter Store. Take the SQLite write
// lock BEFORE reading, including across distinct handles/processes. A failed
// update or commit must prevent provider dispatch.
func (s *Store) UpdateLLMBudget(ctx context.Context, update func([]byte) ([]byte, error)) error {
	const key = "llm.budget.v1"
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: LLM budget begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(ctx, `INSERT INTO connector_state (name, value, updated_at)
		VALUES (?, '{}', '') ON CONFLICT(name) DO UPDATE SET value = connector_state.value`, key); err != nil {
		return fmt.Errorf("store: LLM budget lock: %w", err)
	}
	var value []byte
	if err = tx.QueryRowContext(ctx, `SELECT value FROM connector_state WHERE name = ?`, key).Scan(&value); err != nil {
		return fmt.Errorf("store: LLM budget read: %w", err)
	}
	next, err := update(value)
	if err != nil {
		return err
	}
	if err = saveConnectorState(ctx, tx, key, string(next)); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("store: LLM budget commit: %w", err)
	}
	return nil
}
