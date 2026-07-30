// SPDX-License-Identifier: FSL-1.1-ALv2
package zabbix_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/zabbix"
)

func TestProblemContext_DecodesAckActionAndMaintenanceSuppression(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[{
			"eventid":"4521","severity":"4","clock":"1750000000","r_clock":"0","name":"High CPU",
			"opdata":"cpu 97%","cause_eventid":"0",
			"acknowledges":[{"clock":"1750000100","message":"looking","action":"6","username":"alice"}],
			"suppression_data":[{"maintenanceid":"12","userid":"0","suppress_until":"1750003600"}]
		}],"id":1}`))
	}))
	defer srv.Close()
	c := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "t"})
	pd, err := c.ProblemContext(context.Background(), "4521")
	if err != nil {
		t.Fatal(err)
	}
	if len(pd.Acknowledges) != 1 || !pd.Acknowledges[0].Acknowledged {
		// action "6" carries bit 2 (ack) + bit 4 (message); the decoder must
		// read bit 2 as ack — the 7.0 doc's "6 = ack" is a verified misprint.
		t.Fatalf("ack decode wrong: %+v", pd.Acknowledges)
	}
	if pd.Acknowledges[0].User != "alice" || pd.Acknowledges[0].Message != "looking" {
		t.Fatalf("ack fields wrong: %+v", pd.Acknowledges[0])
	}
	if pd.Suppression.Kind != "maintenance" {
		t.Fatalf("suppression: got %q want maintenance", pd.Suppression.Kind)
	}
	if !pd.Ongoing {
		t.Fatal("r_clock=0 means ongoing")
	}
}

func TestHostContext_ReadsMaintenanceAndInterfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[{
			"name":"DB primary","description":"the db","maintenance_status":"1",
			"hostgroups":[{"name":"Databases"}],
			"inventory":{"location":"riga-dc1","poc_1_name":"bob"},
			"parentTemplates":[{"name":"Linux by Zabbix agent"}],
			"interfaces":[{"ip":"10.0.0.5","dns":"","available":"2","error":"timeout"}]
		}],"id":1}`))
	}))
	defer srv.Close()
	c := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "t"})
	top, err := c.HostContext(context.Background(), "db01")
	if err != nil {
		t.Fatal(err)
	}
	if !top.MaintenanceActive {
		t.Fatal("maintenance_status=1 must read as active")
	}
	if len(top.Interfaces) != 1 || top.Interfaces[0].Available != "2" || top.Interfaces[0].Addr != "10.0.0.5" {
		t.Fatalf("interfaces: %+v", top.Interfaces)
	}
	if top.Inventory["location"] != "riga-dc1" {
		t.Fatalf("inventory: %+v", top.Inventory)
	}
	if len(top.Groups) != 1 || top.Groups[0] != "Databases" {
		t.Fatalf("host groups (selectHostGroups): %+v", top.Groups)
	}
}

func TestHostContext_InventoryDisabledReturnsEmptyArray(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[{
			"name":"web01","description":"","maintenance_status":"0",
			"hostgroups":[],"inventory":[],"parentTemplates":[],"interfaces":[]
		}],"id":1}`))
	}))
	defer srv.Close()
	c := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "t"})
	top, err := c.HostContext(context.Background(), "web01")
	if err != nil {
		t.Fatalf("inventory-disabled host must decode cleanly, got %v", err)
	}
	if len(top.Inventory) != 0 {
		t.Fatalf("want empty inventory, got %+v", top.Inventory)
	}
}

func TestFlapCount_UsesCountOutputAndPluralObjectids(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":"7","id":1}`))
	}))
	defer srv.Close()
	c := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "t"})
	n, err := c.FlapCount(context.Background(), "22713", timeNowMinus24h())
	if err != nil || n != 7 {
		t.Fatalf("got (%d,%v)", n, err)
	}
}

func timeNowMinus24h() time.Time { return time.Now().Add(-24 * time.Hour) }
