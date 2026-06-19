// SPDX-License-Identifier: FSL-1.1-ALv2

// Package ingress implements the inbound webhook host. The host owns the
// cross-cutting concerns shared by every inbound source — per-route bearer
// auth (constant-time), the 1 MiB body cap, the JSON Content-Type guard, the
// audit row, GET /health, and the never-5xx contract. Each Receiver owns parse
// + persist + hand-off for ITS OWN payload type and its own sink. Alertmanager
// alerts route to the correlator; change events route to the change store and
// never touch the correlator.
package ingress

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/health"
	"github.com/alertint/alertint-agent/internal/store"
)

// MaxBodyBytes is the cap on inbound request bodies.
const MaxBodyBytes = 1 << 20 // 1 MiB

// Default HTTP server timeouts. cmd/alertint applies these when wiring up the
// http.Server.
const (
	DefaultReadTimeout     = 10 * time.Second
	DefaultWriteTimeout    = 10 * time.Second
	DefaultIdleTimeout     = 60 * time.Second
	DefaultShutdownTimeout = 10 * time.Second
)

// Receiver is one inbound webhook source mounted on the shared host. The host
// owns auth, the cap, the Content-Type guard, the audit row, and never-5xx; the
// receiver owns parse + persist + hand-off for its OWN payload type.
type Receiver interface {
	Route() string // e.g. "POST /webhook/alertmanager"
	Name() string  // audit/log actor label: "alertmanager" | "change"
	Token() []byte // per-route bearer token
	// Ingest parses, persists, and hands off the body. A returned error maps to
	// HTTP 400 (bad payload); it must NEVER be used for downstream/persist
	// failures (those are logged and swallowed, so the host still answers 204).
	Ingest(ctx context.Context, body []byte) (Summary, error)
}

// Summary is what a Receiver returns to the host on a successful (non-4xx)
// ingest. The host appends exactly one audit row from it: actor=Receiver.Name(),
// kind=Summary.Kind, payload=Summary.Audit. The receiver owns the audit payload
// shape so each payload type records the fields that matter to it.
type Summary struct {
	Kind  string         // audit kind, e.g. "alert.received" | "change.received"
	Audit map[string]any // receiver-owned audit payload (hashed into the chain)
}

// Server is the inbound webhook host. Construct with New; mount Handler() on an
// http.Server bound to receivers.address.
type Server struct {
	store     *store.Store
	auditor   *audit.Auditor
	receivers []Receiver
	logger    *slog.Logger
	health    *health.Registry
}

// Options configures a Server.
type Options struct {
	Store     *store.Store
	Auditor   *audit.Auditor
	Receivers []Receiver   // at least one
	Logger    *slog.Logger // optional; defaults to slog.Default()
	Health    *health.Registry
}

// New constructs the host. It errors if any required field is missing.
func New(opts Options) (*Server, error) {
	if opts.Store == nil {
		return nil, errors.New("ingress: Store is required")
	}
	if opts.Auditor == nil {
		return nil, errors.New("ingress: Auditor is required")
	}
	if len(opts.Receivers) == 0 {
		return nil, errors.New("ingress: at least one Receiver is required")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		store:     opts.Store,
		auditor:   opts.Auditor,
		receivers: opts.Receivers,
		logger:    logger,
		health:    opts.Health,
	}, nil
}

// Handler mounts each receiver's route plus the shared GET /health.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	for _, r := range s.receivers {
		mux.HandleFunc(r.Route(), s.handleReceiver(r))
	}
	mux.HandleFunc("GET /health", s.handleHealth)
	return mux
}

// handleReceiver returns the shared pipeline for one receiver: auth →
// Content-Type guard → cap → read → Ingest → audit → 204. Never 5xx.
func (s *Server) handleReceiver(r Receiver) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		if !authenticate(req, r.Token()) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !isJSONContentType(req.Header.Get("Content-Type")) {
			http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
			return
		}
		req.Body = http.MaxBytesReader(w, req.Body, MaxBodyBytes)
		defer func() { _ = req.Body.Close() }()

		body, err := io.ReadAll(req.Body)
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				http.Error(w, fmt.Sprintf("body too large (max %d bytes)", MaxBodyBytes), http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "could not read body: "+err.Error(), http.StatusBadRequest)
			return
		}

		sum, err := r.Ingest(ctx, body)
		if err != nil {
			// Bad payload only — never downstream failures. 400, never 5xx.
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if appendErr := s.auditor.Append(ctx, r.Name(), sum.Kind, sum.Audit); appendErr != nil {
			s.logger.Error("audit append failed",
				slog.String("kind", sum.Kind),
				slog.String("err", appendErr.Error()),
			)
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	status := "ok"
	code := http.StatusOK
	if err := s.store.DB().PingContext(r.Context()); err != nil {
		status = "degraded"
		code = http.StatusServiceUnavailable
	}
	body := struct {
		Status       string          `json:"status"`
		Integrations []health.Status `json:"integrations,omitempty"`
	}{
		Status:       status,
		Integrations: s.health.Run(r.Context()),
	}
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		s.logger.Warn("ingress: encode health response", "err", err)
	}
}

// authenticate does a constant-time bearer compare against the receiver's token.
func authenticate(r *http.Request, token []byte) bool {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	got := []byte(strings.TrimSpace(auth[len(prefix):]))
	if len(got) != len(token) {
		return false
	}
	return subtle.ConstantTimeCompare(got, token) == 1
}

func isJSONContentType(ct string) bool {
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), "application/json")
}
