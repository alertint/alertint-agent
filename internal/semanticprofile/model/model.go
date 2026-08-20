// SPDX-License-Identifier: FSL-1.1-ALv2

// Package model defines advisory semantic-profile history without importing
// either the store or inference service.
package model

import (
	"encoding/json"
	"time"
)

// Profile may widen evidence consideration or horizon only; it has no
// membership, Attention, policy, or notification authority.
type Profile struct {
	Signature            string   `json:"signature"`
	SubjectKind          string   `json:"subject_kind"`
	EventKind            string   `json:"event_kind"`
	PossibleRole         string   `json:"possible_role"`
	CandidateScope       []string `json:"candidate_scope"`
	CompanionSignalKinds []string `json:"companion_signal_kinds"`
	HorizonTier          string   `json:"horizon_tier"`
	UsefulCapabilities   []string `json:"useful_capabilities"`
	Uncertainty          []string `json:"uncertainty"`
}

type Origin string

const (
	OriginInferred   Origin = "inferred"
	OriginCorrection Origin = "correction"
)

// ProfileVersion is immutable and advances only through optimistic concurrency.
type ProfileVersion struct {
	ID                string          `json:"id"`
	SignatureKey      string          `json:"signature_key"`
	Version           int             `json:"version"`
	Source            string          `json:"source"`
	SignatureMaterial json.RawMessage `json:"signature_material"`
	Profile           Profile         `json:"profile"`
	Origin            Origin          `json:"origin"`
	InputDigest       string          `json:"input_digest"`
	Model             string          `json:"model,omitempty"`
	PromptVersion     string          `json:"prompt_version,omitempty"`
	TokenUsage        json.RawMessage `json:"token_usage,omitempty"`
	AssertedBy        string          `json:"asserted_by,omitempty"`
	CreatedAt         time.Time       `json:"created_at"`
	SupersededAt      *time.Time      `json:"superseded_at,omitempty"`
}

// History provides the current head alongside immutable versions.
type History struct {
	SignatureKey   string           `json:"signature_key"`
	CurrentVersion int              `json:"current_version"`
	Versions       []ProfileVersion `json:"versions"`
}
