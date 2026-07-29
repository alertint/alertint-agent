// SPDX-License-Identifier: FSL-1.1-ALv2

package ingress

import (
	"strings"
	"testing"
)

func TestParseZabbix_DecodesFullPayload(t *testing.T) {
	body := []byte(`{
		"event_id": "9134",
		"status": "PROBLEM",
		"severity": "High",
		"nseverity": "4",
		"host": "db01",
		"host_visible": "DB primary",
		"trigger_id": "22713",
		"trigger_name": "Disk space is critically low",
		"item_key": "vfs.fs.size[/,pused]",
		"item_value": "97.1",
		"tags": [{"tag":"service","value":"billing"},{"tag":"scope","value":"capacity"}],
		"clock": "2026.07.30 14:03:22",
		"recovery_clock": "",
		"generator_url": "https://zbx.example.com/tr_events.php?triggerid=22713&eventid=9134"
	}`)
	ev, err := ParseZabbix(body)
	if err != nil {
		t.Fatal(err)
	}
	if ev.EventID != "9134" || ev.Status != "PROBLEM" || ev.Host != "db01" {
		t.Fatalf("core fields wrong: %+v", ev)
	}
	if len(ev.Tags) != 2 || ev.Tags[0].Tag != "service" || ev.Tags[0].Value != "billing" {
		t.Fatalf("tags wrong: %+v", ev.Tags)
	}
	if ev.NSeverity != "4" {
		t.Fatalf("nseverity: %q", ev.NSeverity)
	}
}

func TestParseZabbix_Rejections(t *testing.T) {
	cases := []struct {
		name, body, wantErr string
	}{
		{"invalid json", `{`, "invalid JSON"},
		{"missing event_id", `{"status":"PROBLEM","host":"h","trigger_name":"t"}`, "event_id is required"},
		{"bad status", `{"event_id":"1","status":"NOPE","host":"h","trigger_name":"t"}`, `status "NOPE"`},
		{"missing host", `{"event_id":"1","status":"PROBLEM","trigger_name":"t"}`, "host is required"},
		{"missing trigger_name", `{"event_id":"1","status":"PROBLEM","host":"h"}`, "trigger_name is required"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseZabbix([]byte(c.body))
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("want error containing %q, got %v", c.wantErr, err)
			}
		})
	}
}

func TestParseZabbix_EmptyTagsTolerated(t *testing.T) {
	for _, tags := range []string{`[]`, `null`} {
		body := []byte(`{"event_id":"1","status":"RESOLVED","host":"h","trigger_name":"t","tags":` + tags + `}`)
		ev, err := ParseZabbix(body)
		if err != nil {
			t.Fatalf("tags=%s: %v", tags, err)
		}
		if len(ev.Tags) != 0 {
			t.Fatalf("tags=%s: want empty, got %+v", tags, ev.Tags)
		}
	}
}
