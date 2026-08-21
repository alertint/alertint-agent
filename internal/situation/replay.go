// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import "github.com/alertint/alertint-agent/internal/situation/model"

// boundaryHook is the crash-injection test seam threaded through the
// durable I/O boundaries Controller and the durable workers own: Situation-
// input apply, L1 completion, L2 completion, the authoritative transition
// commit, and every outward Slack effect (post response, coordinate commit,
// root edit, thread/broadcast reply). Production constructors never set it —
// it stays nil, so runBoundaryHook is always a no-op outside a test that
// deliberately injects one via the SetBoundaryHookForTest methods below.
//
// The receiver-commit, correlation-commit, and observation boundaries have
// no hook here: they are each already a single, separately callable public
// commit (internal/ingress's Receiver.Ingest, internal/correlator's
// Correlator.ApplyDelivery, and internal/observation's Runner.Execute) with
// nothing of this package's own to interrupt mid-call. A crash immediately
// after one of them is exercised by simply not calling the next worker
// before "restarting" — see controller_integration_test.go.
type boundaryHook func(name string) error

// runBoundaryHook invokes hook when one is set, and is a plain no-op
// otherwise — the one call site every injection point in this package
// shares.
func runBoundaryHook(hook boundaryHook, name string) error {
	if hook == nil {
		return nil
	}
	return hook(name)
}

// SetBoundaryHookForTest installs the crash-injection seam on c. It exists
// only for tests (internal/situation's own replay corpus and the real-store
// crash-boundary suite in controller_integration_test.go) — no production
// constructor calls it, and c.hook stays nil otherwise.
func (c *Controller) SetBoundaryHookForTest(hook func(name string) error) { c.hook = hook }

// SetBoundaryHookForTest installs the crash-injection seam on w. Test-only;
// see Controller.SetBoundaryHookForTest.
func (w *InputWorker) SetBoundaryHookForTest(hook func(name string) error) { w.hook = hook }

// SetBoundaryHookForTest installs the crash-injection seam on w. Test-only;
// see Controller.SetBoundaryHookForTest.
func (w *NotificationWorker) SetBoundaryHookForTest(hook func(name string) error) { w.hook = hook }

// coordinateCommitBoundary names the boundary hook fired once Slack has
// accepted one notification intent's effect, immediately before the local
// coordinate commit that records it — chosen by intent kind so a test can
// target a root create's coordinate commit distinctly from a later root
// edit or thread/broadcast reply, even though all three share the same
// NotificationWorker code path.
func coordinateCommitBoundary(kind model.NotificationKind) string {
	switch kind {
	case model.NotificationSituationRootEdit:
		return "root_edit"
	case model.NotificationSituationThreadReply, model.NotificationSituationBroadcastReply:
		return "thread_reply"
	default:
		return "slack_coordinate_commit"
	}
}

// ReplayExpectation is one fixture's declared outcome. Every field is a
// closed, deterministic projection of the replay run: how many Situations
// existed, how many times the main channel was interrupted, the ordered
// lifecycle of every committed transition, the causality of the last
// committed Assessment, how many L1 investigations were dispatched, the
// final lifecycle, the last observed envelope evaluation result, and the
// ordered notification intent kinds produced.
type ReplayExpectation struct {
	SituationCount    int             `json:"situation_count"`
	MainChannelPokes  int             `json:"main_channel_pokes"`
	Transitions       []string        `json:"transitions"`
	Causality         string          `json:"causality"`
	L1Runs            int             `json:"l1_runs"`
	FinalLifecycle    model.Lifecycle `json:"final_lifecycle"`
	EnvelopeResult    string          `json:"envelope_result"`
	NotificationKinds []string        `json:"notification_kinds"`
}
