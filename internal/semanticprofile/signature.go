// SPDX-License-Identifier: FSL-1.1-ALv2

// Package semanticprofile builds deterministic advisory signatures and
// validates closed-schema advisory profiles. It never asserts source
// identity or lifecycle authority — see internal/semanticprofile/model for
// the shapes this package operates over.
package semanticprofile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	profilemodel "github.com/alertint/alertint-agent/internal/semanticprofile/model"
)

// signatureMaterial is the canonical, deterministic JSON shape hashed into a
// Signature's Digest. Exactly one of the three provenance shapes below is
// populated per Mode; the unused fields are omitted so two different modes
// can never coincidentally hash to the same material.
type signatureMaterial struct {
	Schema         int      `json:"schema"`
	Mode           string   `json:"mode"`
	Source         string   `json:"source"`
	SignalID       string   `json:"signal_id,omitempty"`
	Version        *string  `json:"version,omitempty"`
	AlertName      string   `json:"alert_name,omitempty"`
	LabelKeys      []string `json:"label_keys,omitempty"`
	AnnotationKeys []string `json:"annotation_keys,omitempty"`
	TemplateID     string   `json:"template_id,omitempty"`
}

// BuildSignature derives one deterministic Signature from in, following
// spec.md's exact precedence: a proven (signal ID, version) pair; else a
// proven signal ID alone with an explicit missing version; else source,
// alert name, sorted label/annotation key sets, and any adapter-proven
// template identity. It never reads concrete label/annotation VALUES,
// arrival clocks, fingerprints, run IDs, or generator-URL query parameters —
// those never appear in SignatureInput's fields at all, so this function
// cannot accidentally consume them.
func BuildSignature(in profilemodel.SignatureInput) (profilemodel.Signature, error) {
	if in.Source == "" {
		return profilemodel.Signature{}, errors.New("semanticprofile: signature requires a source")
	}
	if err := validateKeyChars(in.LabelKeys); err != nil {
		return profilemodel.Signature{}, fmt.Errorf("semanticprofile: label keys: %w", err)
	}
	if err := validateKeyChars(in.AnnotationKeys); err != nil {
		return profilemodel.Signature{}, fmt.Errorf("semanticprofile: annotation keys: %w", err)
	}

	var mat signatureMaterial
	mat.Schema = profilemodel.SignatureAlgoVersion
	mat.Source = in.Source

	switch {
	case in.ProvenSignalID != "" && in.ProvenVersion != "":
		mat.Mode = profilemodel.SignatureModeSignalVersion
		mat.SignalID = in.ProvenSignalID
		v := in.ProvenVersion
		mat.Version = &v
	case in.ProvenSignalID != "":
		mat.Mode = profilemodel.SignatureModeSignalIDOnly
		mat.SignalID = in.ProvenSignalID
		mat.Version = nil // explicit missing version stays absent, never fabricated
	default:
		mat.Mode = profilemodel.SignatureModeFallback
		mat.AlertName = in.AlertName
		mat.LabelKeys = sortedCopy(in.LabelKeys)
		mat.AnnotationKeys = sortedCopy(in.AnnotationKeys)
		mat.TemplateID = in.ProvenTemplateID
	}

	payload, err := json.Marshal(mat)
	if err != nil {
		return profilemodel.Signature{}, fmt.Errorf("semanticprofile: marshal signature material: %w", err)
	}
	if len(payload) > profilemodel.MaxSignatureMaterialBytes {
		return profilemodel.Signature{}, profilemodel.ErrOversizeSignatureMaterial
	}

	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])

	return profilemodel.Signature{
		Key:           in.Source + ":advisory:sha256:" + digest,
		Digest:        digest,
		SchemaVersion: profilemodel.SignatureAlgoVersion,
		Material:      payload,
		Mode:          mat.Mode,
		AdvisoryOnly:  mat.Mode == profilemodel.SignatureModeFallback,
	}, nil
}

func sortedCopy(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	sort.Strings(out)
	return out
}

func validateKeyChars(keys []string) error {
	for _, k := range keys {
		if len(k) > profilemodel.MaxSignatureKeyChars {
			return fmt.Errorf("key %q exceeds %d characters", k, profilemodel.MaxSignatureKeyChars)
		}
	}
	return nil
}
