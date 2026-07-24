// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"encoding/json"
	"testing"
)

func TestParseExpectation(t *testing.T) {
	e, err := parseExpectation(json.RawMessage(`{"cause_alert":"NodeNetworkInterfaceFlapping","cause_series":["node_network_up"],"severity_rank":"medium","must_mention":["NIC","worker-14"],"must_not_conclude":["AZ outage"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if e.CauseAlert != "NodeNetworkInterfaceFlapping" || len(e.MustMention) != 2 {
		t.Fatalf("%+v", e)
	}

	if _, err := parseExpectation(json.RawMessage(`{"cause_alert":"X"}`)); err == nil {
		t.Fatal("expectation with no graded field accepted")
	}
	if _, err := parseExpectation(json.RawMessage(`{"must_mention":["x"],"bogus":1}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := parseExpectation(nil); err == nil {
		t.Fatal("missing expectation accepted")
	}
}

func TestSynthesizeNote(t *testing.T) {
	e := Expectation{CauseAlert: "NodeNetworkInterfaceFlapping",
		MustMention: []string{"NIC", "worker-14"}, MustNotConclude: []string{"AZ outage"}}
	got := synthesizeNote("correction", e)
	want := "corrected: cause NodeNetworkInterfaceFlapping; must mention NIC, worker-14; not AZ outage"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if got := synthesizeNote("confirmation", Expectation{MustMention: []string{"disk full"}}); got != "confirmed: must mention disk full" {
		t.Fatalf("got %q", got)
	}
}
