// SPDX-License-Identifier: FSL-1.1-ALv2

package llm

import (
	"errors"
	"fmt"
)

// APIError is a non-retryable HTTP status from the provider. Message holds
// whatever the provider client chose to surface after the status (already
// excerpt-bounded by the client); dependency-health classification reads
// only StatusCode and never persists Message.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("llm: api error: HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("llm: api error: HTTP %d: %s", e.StatusCode, e.Message)
}

// ErrResponseInvalid marks a 2xx reply the client could not turn into a JSON
// object: no text block/choice, unparsable envelope, or non-JSON text.
var ErrResponseInvalid = errors.New("llm: response invalid")
