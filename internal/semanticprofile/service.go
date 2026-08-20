// SPDX-License-Identifier: FSL-1.1-ALv2

package semanticprofile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/llm"
	profilemodel "github.com/alertint/alertint-agent/internal/semanticprofile/model"
	"github.com/alertint/alertint-agent/internal/store"
)

type (
	Profile        = profilemodel.Profile
	ProfileVersion = profilemodel.ProfileVersion
	History        = profilemodel.History
	Origin         = profilemodel.Origin
)

const (
	OriginInferred   = profilemodel.OriginInferred
	OriginCorrection = profilemodel.OriginCorrection
)

// ErrVersionConflict is returned when a correction names an obsolete head.
var ErrVersionConflict = errors.New("semanticprofile: version conflict")

// Store is the narrow persistence boundary the service needs.
type Store interface {
	SemanticProfile(context.Context, string) (*profilemodel.History, error)
	AppendSemanticProfileVersion(context.Context, int, profilemodel.ProfileVersion) error
}

// AuditSink records required, redacted profile audit events durably.
type AuditSink interface {
	Append(context.Context, string, string, any) error
}

// LLMClient is intentionally completion-only: semantic inference has no tool
// surface and cannot mutate an operated system.
type LLMClient interface {
	Complete(context.Context, string, llm.Prompt, []string) (llm.Completion, error)
}

// Service owns optional, fail-open semantic inference and confirmed profile
// corrections. Its outputs remain advisory.
type Service struct {
	store         Store
	llm           LLMClient
	promptVersion string
	model         string
	auditor       AuditSink
}

func New(st Store, client LLMClient, promptVersion, model string, auditors ...AuditSink) *Service {
	var auditor AuditSink
	if len(auditors) > 0 {
		auditor = auditors[0]
	} else if concreteStore, ok := st.(*store.Store); ok {
		auditor = audit.New(concreteStore.DB())
	}
	return &Service{store: st, llm: client, promptVersion: promptVersion, model: model, auditor: auditor}
}

// Get returns immutable profile history for one signature.
func (s *Service) Get(ctx context.Context, signature string) (*History, error) {
	if s == nil || s.store == nil {
		return nil, errors.New("semanticprofile: store is required")
	}
	if strings.TrimSpace(signature) == "" {
		return nil, errors.New("semanticprofile: signature is required")
	}
	return s.store.SemanticProfile(ctx, signature)
}

// InferIfMissing returns the cached profile or makes one bounded, advisory LLM
// request. Any inference failure is fail-open: deliveries were persisted before
// this call and no profile is returned.
func (s *Service) InferIfMissing(ctx context.Context, d store.AlertDelivery) (*History, error) {
	if s == nil || s.store == nil || s.llm == nil {
		return nil, nil
	}
	signature, material := signatureMaterial(d)
	history, err := s.Get(ctx, signature)
	if err == nil {
		return history, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	completion, err := s.llm.Complete(ctx, systemPrompt, inferencePrompt(d, signature), profileFields)
	if err != nil {
		if err := s.audit(ctx, "semantic_profile.inference_rejected", map[string]any{"signature": signature, "reason": "llm_failed"}); err != nil {
			return nil, err
		}
		return nil, nil
	}
	profile, err := decodeProfile(completion.Raw, signature)
	if err != nil {
		if auditErr := s.audit(ctx, "semantic_profile.inference_rejected", map[string]any{"signature": signature, "reason": "invalid_profile"}); auditErr != nil {
			return nil, auditErr
		}
		return nil, nil
	}
	usage, err := json.Marshal(map[string]int{
		"input_tokens": completion.InputTokens, "output_tokens": completion.OutputTokens,
		"cache_creation_input_tokens": completion.CacheCreationInputTokens, "cache_read_input_tokens": completion.CacheReadInputTokens,
	})
	if err != nil {
		return nil, nil
	}
	modelName := completion.Model
	if modelName == "" {
		modelName = s.model
	}
	v := ProfileVersion{
		ID: uuid.NewString(), SignatureKey: signature, Source: limitText(d.Source, maxSourceBytes), SignatureMaterial: material,
		Profile: profile, Origin: OriginInferred, InputDigest: inputDigest(d.PayloadDigest, material),
		Model: modelName, PromptVersion: s.promptVersion, TokenUsage: usage, CreatedAt: time.Now().UTC(),
	}
	if err := s.store.AppendSemanticProfileVersion(ctx, 0, v); err != nil {
		if auditErr := s.audit(ctx, "semantic_profile.inference_rejected", map[string]any{"signature": signature, "reason": "head_advance_failed"}); auditErr != nil {
			return nil, auditErr
		}
		return nil, nil
	}
	if err := s.audit(ctx, "semantic_profile.inferred", map[string]any{"signature": signature, "version": 1, "input_digest": v.InputDigest, "model": modelName, "prompt_version": s.promptVersion}); err != nil {
		return nil, err
	}
	if err := s.audit(ctx, "semantic_profile.head_advanced", map[string]any{"signature": signature, "from_version": 0, "to_version": 1, "origin": v.Origin}); err != nil {
		return nil, err
	}
	return s.Get(ctx, signature)
}

// Correction is a confirmed replacement profile at one expected head version.
// Raw must contain exactly the profile schema, never controller authority.
type Correction struct {
	Signature       string          `json:"signature"`
	ExpectedVersion int             `json:"expected_version"`
	Raw             json.RawMessage `json:"profile"`
	Confirmed       bool            `json:"confirmed"`
	ConfirmedBy     string          `json:"confirmed_by"`
}

// Correct appends an immutable operator-confirmed profile version.
func (s *Service) Correct(ctx context.Context, c Correction) (*ProfileVersion, error) {
	if s == nil || s.store == nil {
		return nil, errors.New("semanticprofile: store is required")
	}
	if strings.TrimSpace(c.Signature) == "" {
		return nil, errors.New("semanticprofile: signature is required")
	}
	if len(c.Signature) > maxProfileValueBytes {
		return nil, errors.New("semanticprofile: signature is too large")
	}
	history, err := s.Get(ctx, c.Signature)
	if err != nil {
		return nil, err
	}
	if c.ExpectedVersion != history.CurrentVersion {
		if err := s.audit(ctx, "semantic_profile.correction_rejected", map[string]any{"signature": c.Signature, "expected_version": c.ExpectedVersion, "current_version": history.CurrentVersion, "reason": "version_conflict"}); err != nil {
			return nil, err
		}
		return nil, ErrVersionConflict
	}
	if !c.Confirmed {
		return nil, errors.New("semanticprofile: correction confirmation is required")
	}
	if strings.TrimSpace(c.ConfirmedBy) == "" {
		return nil, errors.New("semanticprofile: asserted attribution is required")
	}
	if len(c.ConfirmedBy) > maxAttributionBytes {
		return nil, errors.New("semanticprofile: asserted attribution is too large")
	}
	profile, err := decodeProfile(c.Raw, c.Signature)
	if err != nil {
		return nil, err
	}
	current := history.Versions[len(history.Versions)-1]
	v := ProfileVersion{
		ID: uuid.NewString(), SignatureKey: c.Signature, Source: current.Source,
		SignatureMaterial: current.SignatureMaterial, Profile: profile, Origin: OriginCorrection,
		InputDigest: inputDigest(string(c.Raw), nil), AssertedBy: strings.TrimSpace(c.ConfirmedBy), CreatedAt: time.Now().UTC(),
	}
	if err := s.store.AppendSemanticProfileVersion(ctx, c.ExpectedVersion, v); err != nil {
		if errors.Is(err, store.ErrVersionConflict) {
			if auditErr := s.audit(ctx, "semantic_profile.correction_rejected", map[string]any{"signature": c.Signature, "expected_version": c.ExpectedVersion, "current_version": history.CurrentVersion, "reason": "version_conflict"}); auditErr != nil {
				return nil, auditErr
			}
			return nil, ErrVersionConflict
		}
		return nil, err
	}
	updated, err := s.Get(ctx, c.Signature)
	if err != nil {
		return nil, err
	}
	result := &updated.Versions[len(updated.Versions)-1]
	if err := s.audit(ctx, "semantic_profile.corrected", map[string]any{"signature": c.Signature, "version": result.Version, "input_digest": result.InputDigest, "asserted_by": result.AssertedBy}); err != nil {
		return nil, err
	}
	if err := s.audit(ctx, "semantic_profile.head_advanced", map[string]any{"signature": c.Signature, "from_version": c.ExpectedVersion, "to_version": result.Version, "origin": result.Origin}); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Service) audit(ctx context.Context, kind string, payload map[string]any) error {
	if s.auditor == nil {
		return errors.New("semanticprofile: required audit sink is unavailable")
	}
	if err := s.auditor.Append(ctx, "semanticprofile", kind, payload); err != nil {
		return fmt.Errorf("semanticprofile: required audit %s: %w", kind, err)
	}
	return nil
}

func decodeProfile(raw json.RawMessage, signature string) (Profile, error) {
	if len(raw) > maxProfileJSONBytes {
		return Profile{}, errors.New("semanticprofile: profile JSON is too large")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return Profile{}, fmt.Errorf("semanticprofile: profile must be a JSON object: %w", err)
	}
	allowed := make(map[string]bool, len(profileFields))
	for _, field := range profileFields {
		allowed[field] = true
	}
	for field := range fields {
		if !allowed[field] {
			return Profile{}, fmt.Errorf("semanticprofile: unknown field %s", field)
		}
	}
	for _, field := range profileFields {
		if _, ok := fields[field]; !ok {
			return Profile{}, fmt.Errorf("semanticprofile: missing field %s", field)
		}
	}
	var profile Profile
	if err := json.Unmarshal(raw, &profile); err != nil {
		return Profile{}, fmt.Errorf("semanticprofile: decode profile: %w", err)
	}
	if profile.Signature != "" && profile.Signature != signature {
		return Profile{}, errors.New("semanticprofile: profile signature does not match correction signature")
	}
	profile.Signature = signature
	if err := validateProfile(profile); err != nil {
		return Profile{}, err
	}
	return profile, nil
}

func validateProfile(profile Profile) error {
	if !allowed(profile.SubjectKind, "unknown", "database_host", "host", "service", "workload", "cluster", "namespace", "node") {
		return fmt.Errorf("semanticprofile: subject kind %q is invalid", profile.SubjectKind)
	}
	if !allowed(profile.EventKind, "unknown", "resource_saturation", "availability", "latency", "error_rate", "capacity", "database_lock", "slow_query", "configuration_change") {
		return fmt.Errorf("semanticprofile: event kind %q is invalid", profile.EventKind)
	}
	if !allowed(profile.PossibleRole, "unknown", "symptom", "cause", "companion") {
		return fmt.Errorf("semanticprofile: possible role %q is invalid", profile.PossibleRole)
	}
	if !allowed(profile.HorizonTier, "unknown", "minutes", "hours", "days") {
		return fmt.Errorf("semanticprofile: horizon tier %q is invalid", profile.HorizonTier)
	}
	if err := validateProfileList("candidate scopes", profile.CandidateScope, maxSignalKindBytes); err != nil {
		return err
	}
	if err := validateProfileList("companion signal kinds", profile.CompanionSignalKinds, maxSignalKindBytes); err != nil {
		return err
	}
	if err := validateProfileList("useful capabilities", profile.UsefulCapabilities, maxSignalKindBytes); err != nil {
		return err
	}
	if err := validateProfileList("uncertainty", profile.Uncertainty, maxProfileValueBytes); err != nil {
		return err
	}
	for _, scope := range profile.CandidateScope {
		if !allowed(scope, "host", "service", "workload", "cluster", "namespace", "node", "database", "instance") {
			return fmt.Errorf("semanticprofile: candidate scope %q is invalid", scope)
		}
	}
	for _, capability := range profile.UsefulCapabilities {
		if !allowed(capability, "store_read", "prometheus_query", "zabbix_metric_range", "zabbix_problem_history", "loki_query", "sentry_issues", "change_events") {
			return fmt.Errorf("semanticprofile: capability %q is invalid", capability)
		}
	}
	if len(profile.CandidateScope) == 0 || len(profile.UsefulCapabilities) == 0 || len(profile.Uncertainty) == 0 {
		return errors.New("semanticprofile: candidate scope, useful capabilities, and uncertainty are required")
	}
	return nil
}

func validateProfileList(name string, values []string, maxValueBytes int) error {
	if len(values) > maxProfileListEntries {
		return fmt.Errorf("semanticprofile: too many %s", name)
	}
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("semanticprofile: %s must not contain empty values", name)
		}
		if len(value) > maxValueBytes {
			return fmt.Errorf("semanticprofile: %s value is too large", name)
		}
	}
	return nil
}

func allowed(value string, values ...string) bool {
	for _, candidate := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func inputDigest(value string, material json.RawMessage) string {
	h := sha256.New()
	h.Write([]byte(value))
	h.Write(material)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
