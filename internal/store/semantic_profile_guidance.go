// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	profilemodel "github.com/alertint/alertint-agent/internal/semanticprofile/model"
)

const (
	profileGuidanceKeyPageSize     = 64
	profileGuidanceContentPageSize = 16
)

// LoadProfileGuidanceForDeliveries returns one guidance entry per mapped,
// published signature, ordered by signature key, with parallel version IDs.
// Both mappings and heads reflect one committed snapshot. Immutable rows and
// the append-only head journal let subsequent bounded reads release the sole
// connection between pages, including before profile JSON decoding.
func (s *Store) LoadProfileGuidanceForDeliveries(ctx context.Context, deliveryIDs []string) ([]observationmodel.ProfileGuidance, []string, error) {
	if len(deliveryIDs) == 0 {
		return nil, nil, nil
	}
	var mappingFence, headFence int64
	if err := s.db.QueryRowContext(ctx, `SELECT
		COALESCE((SELECT MAX(rowid) FROM delivery_semantic_signatures), 0),
		COALESCE((SELECT MAX(sequence) FROM semantic_profile_head_history), 0)`).Scan(&mappingFence, &headFence); err != nil {
		return nil, nil, fmt.Errorf("store: capture profile guidance snapshot: %w", err)
	}
	keys := make(map[string]struct{})
	for start := 0; start < len(deliveryIDs); start += profileGuidanceKeyPageSize {
		page, err := s.profileGuidanceMappings(ctx, deliveryIDs[start:min(start+profileGuidanceKeyPageSize, len(deliveryIDs))], mappingFence)
		if err != nil {
			return nil, nil, err
		}
		for _, key := range page {
			keys[key] = struct{}{}
		}
	}
	signatures := make([]string, 0, len(keys))
	for key := range keys {
		signatures = append(signatures, key)
	}
	sort.Strings(signatures)
	var heads []profileGuidanceHead
	for start := 0; start < len(signatures); start += profileGuidanceKeyPageSize {
		page, err := s.profileGuidanceHeads(ctx, signatures[start:min(start+profileGuidanceKeyPageSize, len(signatures))], headFence)
		if err != nil {
			return nil, nil, err
		}
		heads = append(heads, page...)
	}
	// The queries return at most one head per key; sort explicitly rather than
	// relying on json_each or index traversal to retain the requested order.
	sort.Slice(heads, func(i, j int) bool { return heads[i].signature < heads[j].signature })
	var guidance []observationmodel.ProfileGuidance
	var versionIDs []string
	for start := 0; start < len(heads); start += profileGuidanceContentPageSize {
		page := heads[start:min(start+profileGuidanceContentPageSize, len(heads))]
		content, err := s.profileGuidanceContent(ctx, page)
		if err != nil {
			return nil, nil, err
		}
		for _, head := range page {
			if err := ctx.Err(); err != nil {
				return nil, nil, err
			}
			var profile profilemodel.Profile
			if err := json.Unmarshal([]byte(content[head.version]), &profile); err != nil {
				return nil, nil, fmt.Errorf("store: unmarshal profile guidance content: %w", err)
			}
			capabilities := make([]observationmodel.Capability, 0, len(profile.UsefulCapabilities))
			for _, capability := range profile.UsefulCapabilities {
				capabilities = append(capabilities, observationmodel.Capability(capability))
			}
			guidance = append(guidance, observationmodel.ProfileGuidance{
				SignatureKey: head.signature, VersionID: head.version, HorizonTier: profile.HorizonTier,
				UsefulCapabilities: capabilities, CandidateScope: profile.CandidateScope,
			})
			versionIDs = append(versionIDs, head.version)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	return guidance, versionIDs, nil
}

func (s *Store) profileGuidanceMappings(ctx context.Context, ids []string, fence int64) ([]string, error) {
	encoded, err := json.Marshal(ids)
	if err != nil {
		return nil, fmt.Errorf("store: encode profile guidance delivery IDs: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT signature_key FROM delivery_semantic_signatures
		WHERE delivery_id IN (SELECT value FROM json_each(?)) AND rowid <= ?`, string(encoded), fence)
	if err != nil {
		return nil, fmt.Errorf("store: query profile guidance mappings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var keys []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, fmt.Errorf("store: scan profile guidance mapping: %w", err)
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate profile guidance mappings: %w", err)
	}
	return keys, nil
}

type profileGuidanceHead struct{ signature, version string }

func (s *Store) profileGuidanceHeads(ctx context.Context, keys []string, fence int64) ([]profileGuidanceHead, error) {
	encoded, err := json.Marshal(keys)
	if err != nil {
		return nil, fmt.Errorf("store: encode profile guidance signatures: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT history.signature_key, history.version_id
		FROM json_each(?) requested JOIN semantic_profile_head_history history ON history.sequence = (
			SELECT sequence FROM semantic_profile_head_history
			WHERE signature_key = requested.value AND sequence <= ? ORDER BY sequence DESC LIMIT 1)
		WHERE history.version_id IS NOT NULL`, string(encoded), fence)
	if err != nil {
		return nil, fmt.Errorf("store: query profile guidance heads: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var heads []profileGuidanceHead
	for rows.Next() {
		var head profileGuidanceHead
		if err := rows.Scan(&head.signature, &head.version); err != nil {
			return nil, fmt.Errorf("store: scan profile guidance head: %w", err)
		}
		heads = append(heads, head)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate profile guidance heads: %w", err)
	}
	return heads, nil
}

func (s *Store) profileGuidanceContent(ctx context.Context, heads []profileGuidanceHead) (map[string]string, error) {
	ids := make([]string, 0, len(heads))
	for _, head := range heads {
		ids = append(ids, head.version)
	}
	encoded, err := json.Marshal(ids)
	if err != nil {
		return nil, fmt.Errorf("store: encode profile guidance versions: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, profile_json FROM semantic_profile_versions
		WHERE id IN (SELECT value FROM json_each(?))`, string(encoded))
	if err != nil {
		return nil, fmt.Errorf("store: query profile guidance content: %w", err)
	}
	defer func() { _ = rows.Close() }()
	content := make(map[string]string, len(heads))
	for rows.Next() {
		var id, profile string
		if err := rows.Scan(&id, &profile); err != nil {
			return nil, fmt.Errorf("store: scan profile guidance content: %w", err)
		}
		content[id] = profile
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate profile guidance content: %w", err)
	}
	return content, nil
}
