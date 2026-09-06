// SPDX-License-Identifier: FSL-1.1-ALv2

// Package model defines the transport-neutral shapes for advisory semantic
// profiles: the deterministic advisory-signature identity, the closed-schema
// Profile content itself, its immutable versions, durable inference-job
// claims, and operator corrections. It imports only the standard library —
// deliberately independent of internal/observation/model, so this package
// carries its own closed capability-name vocabulary rather than importing
// one, matching plan.md's "Observation/profile models import only the
// standard library."
package model

import (
	"encoding/json"
	"errors"
	"time"
)

// Fixed bounds (spec.md "Durable semantic-profile inference"): each meaning
// field is a bounded advisory string, each array has at most eight values,
// uncertainty entries are at most 256 characters, and the whole profile is
// at most 8 KiB. These are not configuration — a schema/prompt version bump
// is required to ever change one.
const (
	MaxMeaningFieldChars      = 128
	MaxUncertaintyChars       = 256
	MaxArrayValues            = 8
	MaxProfileBytes           = 8 * 1024
	MaxSignatureMaterialBytes = 4 * 1024
	MaxSignatureKeyChars      = 256

	ProfileSchemaVersion = 1
	PromptVersion        = 1
	SignatureAlgoVersion = 1
)

// HorizonTier is the closed four-value advisory horizon vocabulary. It can
// only ever widen the controller's observation horizon (ADR-0050); it can
// never shorten the baseline, assert source state, or renew an observation
// timestamp.
const (
	HorizonUnknown = "unknown"
	HorizonMinutes = "minutes"
	HorizonHours   = "hours"
	HorizonDays    = "days"
)

var horizonTiers = map[string]bool{
	HorizonUnknown: true, HorizonMinutes: true, HorizonHours: true, HorizonDays: true,
}

// ValidHorizonTier reports whether h is one of the closed four horizon
// values.
func ValidHorizonTier(h string) bool { return horizonTiers[h] }

// Capability names mirror internal/observation/model's closed seven-name
// vocabulary exactly, duplicated here (never imported) to keep this package
// standard-library-only. Any drift between the two lists is a defect; Task 6
// wiring is the single place both are consulted together.
const (
	CapabilityStoreRead         = "store_read"
	CapabilityPrometheusQuery   = "prometheus_query"
	CapabilityZabbixMetricRange = "zabbix_metric_range"
	CapabilityZabbixProblemHist = "zabbix_problem_history"
	CapabilityLokiQuery         = "loki_query"
	CapabilitySentryIssues      = "sentry_issues"
	CapabilityChangeEvents      = "change_events"
)

var validCapabilities = map[string]bool{
	CapabilityStoreRead: true, CapabilityPrometheusQuery: true, CapabilityZabbixMetricRange: true,
	CapabilityZabbixProblemHist: true, CapabilityLokiQuery: true, CapabilitySentryIssues: true,
	CapabilityChangeEvents: true,
}

// ValidCapabilityName reports whether c is one of the closed seven
// capability names a profile may cite as useful.
func ValidCapabilityName(c string) bool { return validCapabilities[c] }

// Origin is the closed two-value provenance of a Version: model-produced
// inference, or an operator-asserted correction.
const (
	OriginInferred   = "inferred"
	OriginCorrection = "correction"
)

// Profile is the advisory closed-schema content itself — exactly the eight
// fields spec.md names, no tools, no recursive calls, no model-authored
// queries, and no policy/action field of any kind.
type Profile struct {
	SubjectKind          string   `json:"subject_kind"`
	EventKind            string   `json:"event_kind"`
	PossibleRole         string   `json:"possible_role"`
	CandidateScope       []string `json:"candidate_scope"`
	CompanionSignalKinds []string `json:"companion_signal_kinds"`
	HorizonTier          string   `json:"horizon_tier"`
	UsefulCapabilities   []string `json:"useful_capabilities"`
	Uncertainty          []string `json:"uncertainty"`
}

// SignatureInput is the immutable, delivery-derived basis for one advisory
// signature: proven source-signal identity when the adapter can prove it,
// and otherwise the sorted label/annotation key schema plus whatever
// adapter-proven template identity exists. Concrete label/annotation VALUES,
// arrival clocks, fingerprints, run IDs, and generator-URL query parameters
// must never be placed here — the caller (never this package) is
// responsible for supplying only genuinely adapter-proven fields; an
// untrusted annotation cannot claim a source version merely by naming one.
type SignatureInput struct {
	Source string
	// AlertName is the rule-attached alert name, used only in the fallback
	// material (never combined with a proven signal ID/version, which are
	// already sufficient identity on their own).
	AlertName string
	// ProvenSignalID and ProvenVersion are the source adapter's own proven
	// signal identity/version (never derived from arbitrary annotations).
	// ProvenVersion may be empty even when ProvenSignalID is set — spec.md:
	// "If ID exists without version, keep the ID and explicit missing
	// version in advisory material."
	ProvenSignalID string
	ProvenVersion  string
	// ProvenTemplateID is adapter-proven rule/template identity, used only
	// in the fallback material when no proven signal ID exists.
	ProvenTemplateID string
	LabelKeys        []string
	AnnotationKeys   []string
}

// Signature provenance modes — the closed three-value classification of how
// a Signature was derived, persisted alongside it for audit.
const (
	SignatureModeSignalVersion = "signal_version" // proven ID + proven version
	SignatureModeSignalIDOnly  = "signal_id_only" // proven ID, version explicitly absent
	SignatureModeFallback      = "fallback"       // no proven ID: source/name/schema/template
)

// Signature is the deterministic advisory cache identity derived from a
// SignatureInput: a stable Key (used as the durable row key and the MCP
// tool argument), a full un-truncated SHA-256 Digest, the canonical
// signature Material that produced it (for audit — never containing
// concrete resource values), and whether it is AdvisoryOnly (Mode ==
// SignatureModeFallback). An advisory signature permits reuse of
// interpretation only; it never substitutes for source-proven policy
// identity even when AdvisoryOnly is false.
type Signature struct {
	Key           string
	Digest        string
	SchemaVersion int
	Material      json.RawMessage
	Mode          string
	AdvisoryOnly  bool
}

// Version is one immutable, versioned Profile — either a model inference
// outcome or an operator correction. Versions never overwrite each other;
// only the separate CAS-protected head projection advances.
type Version struct {
	ID                  string
	Signature           string
	Version             int
	SchemaVersion       int
	PromptVersion       int
	SemanticInputDigest string
	Origin              string
	Provider            string
	Model               string
	UsageInputTokens    int
	UsageOutputTokens   int
	Profile             Profile
	CreatedAt           time.Time
	AssertedBy          string // non-empty only when Origin == OriginCorrection
}

// Correction is an MCP-submitted, confirmed operator override. ExpectedVersion
// == 0 permits creating a missing head; any other value must match the
// current head exactly (CAS) or ErrVersionConflict is returned.
type Correction struct {
	Signature       string
	ExpectedVersion int
	Profile         Profile
	Confirm         bool
	AssertedBy      string
}

// Inference-job states — the closed four-value durable job lifecycle.
const (
	JobStatePending   = "pending"
	JobStateRunning   = "running"
	JobStateComplete  = "complete"
	JobStateExhausted = "exhausted"
)

// JobClaim is one durable inference-job dispatch claim: the frozen semantic
// input this attempt commits against, and the owner/token/lease fencing
// pair a worker holds it under.
type JobClaim struct {
	JobID               string
	Signature           string
	FrozenInputJSON     json.RawMessage
	FrozenInputDigest   string
	ExpectedHeadVersion int
	Owner               string
	Token               int64
	LeaseExpiresAt      time.Time
	Attempt             int
}

// JobState is the bounded, read-only current state of one signature's
// inference job, for History.
type JobState struct {
	Status     string
	Attempt    int
	RetryAt    *time.Time
	ErrorClass *string
}

// History is GetSemanticProfile's bounded read result: the current head
// (nil if none exists yet), a bounded page of prior versions, the job's
// current state (nil if no job exists), and a cursor for the next page.
type History struct {
	Current    *Version
	Versions   []Version
	Job        *JobState
	NextCursor string
}

// Inference outcomes — the closed vocabulary CompleteSemanticInference
// records for one dispatched attempt.
const (
	InferenceOutcomeAccepted  = "accepted"
	InferenceOutcomeRejected  = "rejected"
	InferenceOutcomeMalformed = "malformed"
	InferenceOutcomeFailed    = "failed"
	InferenceOutcomeStale     = "stale"
)

// InferenceResult is one dispatched attempt's outcome: an optional validated
// Profile (present only for InferenceOutcomeAccepted), the closed outcome,
// whether the request physically started, and bounded usage/provenance
// metadata. It never carries a raw provider response.
type InferenceResult struct {
	Profile           *Profile
	Outcome           string
	RequestStarted    string // "true" | "false" | "unknown"
	UsageInputTokens  int
	UsageOutputTokens int
	Provider          string
	Model             string
	PromptVersion     int
}

// ErrVersionConflict is returned by CorrectSemanticProfile when
// Correction.ExpectedVersion no longer matches the current head (a stale
// CAS).
var ErrVersionConflict = errors.New("semanticprofile: expected version does not match current head")

// ErrOversizeSignatureMaterial is returned by BuildSignature when the
// canonical signature material would exceed MaxSignatureMaterialBytes —
// refused outright, per spec.md, rather than silently truncated into a
// collision.
var ErrOversizeSignatureMaterial = errors.New("semanticprofile: signature material exceeds size bound")

// ErrLeaseLost is returned by profile-store methods when a caller's
// owner/token no longer matches the live job claim.
var ErrLeaseLost = errors.New("semanticprofile: job lease lost")
