// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/alertint/alertint-agent/internal/notify/ntfy"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ConfigureNTFY records non-secret startup policy before the controller starts.
// Existing work survives event changes; destination replacement retires it visibly.
func (s *Store) ConfigureNTFY(ctx context.Context, c ntfy.Config, now time.Time) error {
	if err := c.Validate(); err != nil {
		return err
	}
	events, err := json.Marshal(c.SelectedEvents())
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var old string
	var enabled bool
	if err = tx.QueryRowContext(ctx, "SELECT destination,enabled FROM ntfy_configuration WHERE id=1").Scan(&old, &enabled); err != nil {
		return err
	}
	dest := c.Destination()
	// An omitted destination while disabled pauses the existing installation.
	if !c.Enabled && c.Topic == "" {
		dest = old
	}
	if old != "" && old != dest {
		if _, err = tx.ExecContext(ctx, `UPDATE ntfy_notifications SET status='retired',reason='destination_changed',claim_token=claim_token+1,claim_owner='',lease_until=0 WHERE status IN ('pending','delivering','blocked')`); err != nil {
			return err
		}
	}
	// A previous process cannot acknowledge a startup-recovered claim.
	if _, err = tx.ExecContext(ctx, `UPDATE ntfy_notifications SET status='pending',claim_token=claim_token+1,claim_owner='',lease_until=0,delayed=1 WHERE status='delivering'`); err != nil {
		return err
	}
	if !c.Enabled {
		if _, err = tx.ExecContext(ctx, `UPDATE ntfy_notifications SET delayed=1 WHERE status IN ('pending','blocked')`); err != nil {
			return err
		}
	} else {
		if _, err = tx.ExecContext(ctx, `UPDATE ntfy_notifications SET status='pending',retry_at=?,delayed=1 WHERE status='blocked'`, now.UnixNano()); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE ntfy_configuration SET enabled=?,destination=?,events_json=? WHERE id=1`, c.Enabled, dest, string(events)); err != nil {
		return err
	}
	return tx.Commit()
}

func enqueueNTFYTx(ctx context.Context, tx *sql.Tx, transitions []model.Transition) error {
	if len(transitions) == 0 {
		return nil
	}
	first, t := transitions[0], transitions[len(transitions)-1]
	var enabled bool
	var destination, raw string
	if err := tx.QueryRowContext(ctx, "SELECT enabled,destination,events_json FROM ntfy_configuration WHERE id=1").Scan(&enabled, &destination, &raw); err != nil {
		return err
	}
	if !enabled {
		return nil
	}
	var configured []string
	if err := json.Unmarshal([]byte(raw), &configured); err != nil {
		return err
	}
	var prior *model.Transition
	p, err := scanTransition(tx.QueryRowContext(ctx, `SELECT `+transitionColumns+` FROM situation_transitions WHERE situation_id=? AND sequence<? ORDER BY sequence DESC LIMIT 1`, t.SituationID, first.Sequence))
	if err == nil {
		prior = &p
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var published bool
	// Match the controller's PublicationAuthority, not per-poke priority.
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM situation_transitions WHERE situation_id=? AND sequence<? AND (attention='urgent' OR trim(coalesce(json_extract(projection_json,'$.assessment.sufficient_reason_code'),''))<>''))`, t.SituationID, first.Sequence).Scan(&published); err != nil {
		return err
	}
	// Artifacts and controller/judgment siblings share one committed state
	// change. Combine their selected edges once and render the final state.
	var events []string
	for _, tr := range transitions {
		for _, event := range ntfy.Select(tr, prior, published, configured) {
			if !slices.Contains(events, event) {
				events = append(events, event)
			}
		}
	}
	slices.SortFunc(events, func(a, b string) int { return slices.Index(ntfy.Events, a) - slices.Index(ntfy.Events, b) })
	if len(events) == 0 {
		return nil
	}
	return insertNTFYTx(ctx, tx, ntfyIdentity(destination, t.ID), destination, t, events, false, false)
}

func ntfyIdentity(destination, source string) string {
	sum := sha256.Sum256([]byte(destination + "\x00" + source))
	return "ntfy-" + hex.EncodeToString(sum[:16])
}

func insertNTFYTx(ctx context.Context, tx *sql.Tx, id, dest string, t model.Transition, events []string, catchup, delayed bool) error {
	message := ntfy.Render(t, events, false)
	if catchup {
		message = ntfy.RenderCatchup(t, events, delayed)
	}
	message.ID = id
	payload, err := json.Marshal(message)
	if err != nil {
		return err
	}
	selection, err := json.Marshal(events)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO ntfy_notifications(id,situation_id,transition_id,sequence,destination,events_json,message_json,status,catchup,created_at) VALUES(?,?,?,?,?,?,?,'pending',?,?)`, id, t.SituationID, t.ID, t.Sequence, dest, string(selection), string(payload), catchup, canonicalTime(t.CreatedAt))
	return err
}

// ClaimNTFY leases one eligible head. Only expired claims are
// recovered here; queue policy and payloads are committed before any HTTP call.
func (s *Store) ClaimNTFY(ctx context.Context, owner string, now time.Time, lease time.Duration) ([]ntfy.Claim, error) {
	if owner == "" || lease <= 0 {
		return nil, errors.New("ntfy: owner and positive lease required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	var enabled bool
	if err = tx.QueryRowContext(ctx, "SELECT enabled FROM ntfy_configuration WHERE id=1").Scan(&enabled); err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	if _, err = tx.ExecContext(ctx, `UPDATE ntfy_notifications SET status='pending',delayed=1,claim_owner='',lease_until=0 WHERE status='delivering' AND lease_until<=?`, now.UnixNano()); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT n.id FROM ntfy_notifications n WHERE n.status='pending' AND n.retry_at<=? AND NOT EXISTS(SELECT 1 FROM ntfy_notifications p WHERE p.situation_id=n.situation_id AND p.status IN ('pending','delivering','blocked') AND (p.sequence<n.sequence OR (p.sequence=n.sequence AND p.rowid<n.rowid))) ORDER BY n.created_at,n.rowid LIMIT 1`, now.UnixNano())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return nil, err
	}
	var claims []ntfy.Claim
	for _, id := range ids {
		id, err = compactNTFYTx(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		var c ntfy.Claim
		var raw string
		if err = tx.QueryRowContext(ctx, `UPDATE ntfy_notifications SET status='delivering',claim_owner=?,claim_token=claim_token+1,lease_until=?,attempts=attempts+1 WHERE id=? AND status='pending' RETURNING id,destination,claim_token,attempts,message_json`, owner, now.Add(lease).UnixNano(), id).Scan(&c.ID, &c.Destination, &c.Token, &c.Attempts, &raw); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(raw), &c.Message); err != nil {
			return nil, err
		}
		c.Owner = owner
		claims = append(claims, c)
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return claims, nil
}

func compactNTFYTx(ctx context.Context, tx *sql.Tx, id string) (string, error) {
	var sit, dest string
	var delayed bool
	var sequence int
	if err := tx.QueryRowContext(ctx, `SELECT situation_id,destination,sequence,delayed FROM ntfy_notifications WHERE id=?`, id).Scan(&sit, &dest, &sequence, &delayed); err != nil {
		return "", err
	}
	latest, err := scanTransition(tx.QueryRowContext(ctx, `SELECT `+transitionColumns+` FROM situation_transitions WHERE situation_id=? ORDER BY sequence DESC LIMIT 1`, sit))
	if err != nil {
		return "", err
	}
	if latest.Sequence == sequence {
		return id, nil
	} // unchanged-state retries preserve identity and content
	if !delayed {
		original, loadErr := scanTransition(tx.QueryRowContext(ctx, `SELECT `+transitionColumns+` FROM situation_transitions WHERE situation_id=? AND sequence=?`, sit, sequence))
		if loadErr != nil {
			return "", loadErr
		}
		// Ordinary ordered updates retain their payload. A terminal state or
		// withdrawn/revised action must not replay an obsolete interruption.
		stale := latest.Lifecycle.Terminal() && !original.Lifecycle.Terminal()
		if action := original.ActionContract.OperatorActionRequired; action != nil {
			stale = stale || latest.ActionContract.OperatorActionRequired == nil || *action != *latest.ActionContract.OperatorActionRequired
		}
		if !stale {
			return id, nil
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,events_json FROM ntfy_notifications WHERE situation_id=? AND destination=? AND status IN ('pending','blocked') ORDER BY sequence,rowid`, sit, dest)
	if err != nil {
		return "", err
	}
	defer func() { _ = rows.Close() }()
	var originals, events []string
	for rows.Next() {
		var old, raw string
		if err = rows.Scan(&old, &raw); err != nil {
			_ = rows.Close()
			return "", err
		}
		originals = append(originals, old)
		var selected []string
		if err = json.Unmarshal([]byte(raw), &selected); err != nil {
			_ = rows.Close()
			return "", err
		}
		for _, event := range selected {
			if !slices.Contains(events, event) {
				events = append(events, event)
			}
		}
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return "", err
	}
	replacement := ntfyIdentity(dest, "catchup:"+latest.ID+":"+fmt.Sprint(originals))
	if err = insertNTFYTx(ctx, tx, replacement, dest, latest, events, true, delayed); err != nil {
		return "", err
	}
	for _, old := range originals {
		if _, err = tx.ExecContext(ctx, `UPDATE ntfy_notifications SET status='superseded',reason='ntfy_catchup',replacement_id=?,claim_token=claim_token+1 WHERE id=?`, replacement, old); err != nil {
			return "", err
		}
	}
	return replacement, nil
}

// FinishNTFY fences acknowledgement and schedules indefinite retries. No secrets
// or upstream response bodies are stored as errors.
func (s *Store) FinishNTFY(ctx context.Context, c ntfy.Claim, status, reason string, retryAt, now time.Time) error {
	if status != "delivered" && status != "pending" && status != "blocked" {
		return errors.New("ntfy: invalid delivery outcome")
	}
	var delivered any
	if status == "delivered" {
		delivered = canonicalTime(now)
	}
	res, err := s.db.ExecContext(ctx, `UPDATE ntfy_notifications SET status=?,reason=?,retry_at=?,delayed=CASE WHEN ?='delivered' THEN delayed ELSE 1 END,delivered_at=?,claim_owner='',lease_until=0 WHERE id=? AND status='delivering' AND claim_owner=? AND claim_token=? AND lease_until>?`, status, reason, retryAt.UnixNano(), status, delivered, c.ID, c.Owner, c.Token, now.UnixNano())
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ntfy.ErrClaimLost
	}
	return nil
}
