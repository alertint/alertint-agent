// SPDX-License-Identifier: FSL-1.1-ALv2

package ingress

// DurabilityError marks a failure that happened while trying to durably
// persist an otherwise structurally valid payload — the Store could not
// commit the acceptance transaction (e.g. the database is locked or
// unreachable). The host maps it to HTTP 503 with a fixed public message so
// a well-behaved sender retries the exact same body later. Every other
// Ingest error means the receiver itself rejected the payload as invalid and
// maps to HTTP 400. Never wrap a receiver-side validation failure in
// DurabilityError — it is reserved for a failure to persist a payload the
// receiver has already accepted as valid.
type DurabilityError struct{ Err error }

// Error renders a message for logs. The HTTP response never uses this text
// directly — the host substitutes its own fixed public message so a raw
// driver error (which could name a file path or other internal detail)
// never reaches the caller.
func (e *DurabilityError) Error() string { return "ingress: durable acceptance: " + e.Err.Error() }

// Unwrap exposes Err so errors.As at the host can recognize this failure
// class without depending on anything else about this type.
func (e *DurabilityError) Unwrap() error { return e.Err }
