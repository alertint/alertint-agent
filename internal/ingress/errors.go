// SPDX-License-Identifier: FSL-1.1-ALv2

package ingress

// DurabilityError reports that a syntactically valid delivery could not be
// committed. The host maps only this error class to 503 so senders retry.
type DurabilityError struct{ Err error }

func (e *DurabilityError) Error() string { return "ingress: durable acceptance: " + e.Err.Error() }
func (e *DurabilityError) Unwrap() error { return e.Err }
