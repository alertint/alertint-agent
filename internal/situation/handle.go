// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"encoding/base32"
	"errors"
	"sort"
	"strings"
	"unicode"

	"github.com/google/uuid"
)

const maxPublicHandleBytes = 63

// PublicHandle derives the immutable public identity minted at first
// publication: group values sorted for order-independence, joined with the
// dominant symptom, and slugified. The caller supplies whether the
// unsuffixed handle collides with an existing case-insensitive handle; on
// collision a stable lowercase base32 suffix derived from the Situation ID
// is appended. Plan 1 tests this function but does not mint a handle in
// production — first publication belongs to the notification slice.
func PublicHandle(groupValues []string, dominantSymptom, situationID string, collision bool) (string, error) {
	values := append([]string(nil), groupValues...)
	sort.Strings(values)
	parts := make([]string, 0, len(values)+1)
	parts = append(parts, values...)
	parts = append(parts, dominantSymptom)
	base := slug(strings.Join(parts, "-"))
	if base == "" {
		base = "situation"
	}
	if !collision {
		return truncateSlug(base, maxPublicHandleBytes), nil
	}
	parsed, err := uuid.Parse(situationID)
	if err != nil {
		return "", errors.New("situation: collision handle requires a valid uuid")
	}
	suffix := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(parsed[:]))[:8]
	prefix := truncateSlug(base, maxPublicHandleBytes-1-len(suffix))
	if prefix == "" {
		prefix = "situation"
	}
	return prefix + "-" + suffix, nil
}

func slug(value string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(value) {
		if r >= 'a' && r <= 'z' || unicode.IsDigit(r) && r <= unicode.MaxASCII {
			b.WriteRune(r)
			dash = false
			continue
		}
		if b.Len() > 0 && !dash {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func truncateSlug(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return strings.TrimRight(value[:limit], "-")
}
