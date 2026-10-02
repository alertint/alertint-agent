// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/alertint/alertint-agent/internal/logs"
)

func TestFetchLogs_ExceptionDetailsSurviveAttributeFiltering(t *testing.T) {
	for _, key := range []string{"exception_message", "exception.message", "exception_type", "exception.type"} {
		t.Run(key, func(t *testing.T) {
			message := "HTTP/2 client preface string missing or corrupt. Hex dump for received bytes: 0a"
			if strings.HasSuffix(key, "type") {
				message = "example.protocol.ClientPrefaceException"
			}
			src := &fakeSource{name: "loki", fetched: logs.Fetched{Lines: []logs.Line{
				{Line: "Transport failed", Attrs: map[string]string{key: message, "resource": "same"}},
				{Line: "Transport failed", Attrs: map[string]string{key: message, "resource": "same"}},
			}}}
			e := FetchLogs(context.Background(), src, LogParams{DefaultRangeMinutes: 15, TimeoutSeconds: 5, MaxLines: 50}, alertsWith(map[string]string{"service": "api"}), time.Now(), time.Now(), "inc", nil)
			var b strings.Builder
			renderLogs(&b, e)
			if strings.Count(b.String(), key+"="+message) != 2 {
				t.Fatalf("repeated exception detail missing: %s", b.String())
			}
			if strings.Contains(b.String(), "resource=") {
				t.Fatal("constant resource attribute should still be omitted")
			}
		})
	}
}

func TestFetchLogs_ExceptionDetailsBoundedAndPrioritized(t *testing.T) {
	entries := make([]logs.Line, 0, 3)
	for _, suffix := range []string{"first", "second", "third"} {
		attrs := map[string]string{"exception_message": "connection failed\n" + strings.Repeat("\u754c", 300) + suffix}
		for _, key := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
			value := "shared"
			if suffix == "third" {
				value = "other"
			}
			attrs[key] = value
		}
		entries = append(entries, logs.Line{Line: "Transport failed", Attrs: attrs})
	}
	src := &fakeSource{name: "loki", fetched: logs.Fetched{Lines: entries}}
	e := FetchLogs(context.Background(), src, LogParams{DefaultRangeMinutes: 15, TimeoutSeconds: 5, MaxLines: 50}, alertsWith(map[string]string{"service": "api"}), time.Now(), time.Now(), "inc", nil)
	for _, line := range e.Lines {
		message := line.Attrs["exception_message"]
		if !strings.HasPrefix(message, "connection failed ") || strings.ContainsAny(message, "\r\n") || utf8.RuneCountInString(message) > 256 || !utf8.ValidString(message) {
			t.Fatalf("missing or unbounded exception message: %q", message)
		}
		if len(line.Attrs) > 8 {
			t.Fatalf("attribute count exceeded: %v", line.Attrs)
		}
	}
}
