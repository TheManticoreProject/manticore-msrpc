package mode_monitor

import "testing"

// set builds a snapshot map from endpoints, keyed the same way the monitor does.
func set(endpoints ...endpoint) map[string]endpoint {
	m := make(map[string]endpoint, len(endpoints))
	for _, e := range endpoints {
		m[e.key()] = e
	}
	return m
}

func TestDiffSnapshots(t *testing.T) {
	samr := endpoint{uuid: "12345778-1234-abcd-ef00-0123456789ac", version: "1.0", name: "samr", binding: "ncacn_ip_tcp:10.0.0.5[49664]"}
	srvsvc := endpoint{uuid: "4b324fc8-1670-01d3-1278-5a47bf6ee188", version: "3.0", name: "srvsvc", binding: "ncacn_np:HOST[\\PIPE\\srvsvc]"}
	spool := endpoint{uuid: "12345678-1234-abcd-ef00-0123456789ab", version: "1.0", name: "spoolss", binding: "ncacn_ip_tcp:10.0.0.5[49680]"}

	before := set(samr, srvsvc)
	now := set(samr, spool) // srvsvc disappeared, spool appeared, samr unchanged

	created, deleted := diffSnapshots(before, now)

	if len(created) != 1 || created[0].name != "spoolss" {
		t.Fatalf("created = %+v, want only spoolss", created)
	}
	if len(deleted) != 1 || deleted[0].name != "srvsvc" {
		t.Fatalf("deleted = %+v, want only srvsvc", deleted)
	}
}

func TestDiffSnapshotsNoChange(t *testing.T) {
	e := endpoint{uuid: "12345778-1234-abcd-ef00-0123456789ac", version: "1.0", binding: "ncacn_ip_tcp:10.0.0.5[49664]"}
	snap := set(e)

	created, deleted := diffSnapshots(snap, snap)
	if len(created) != 0 || len(deleted) != 0 {
		t.Fatalf("steady state should report no changes, got created=%d deleted=%d", len(created), len(deleted))
	}
}

// A binding change for the same interface is one endpoint deleted and one created, since an
// endpoint is identified by (uuid, version, binding).
func TestDiffSnapshotsBindingMove(t *testing.T) {
	oldEp := endpoint{uuid: "12345778-1234-abcd-ef00-0123456789ac", version: "1.0", binding: "ncacn_ip_tcp:10.0.0.5[49664]"}
	newEp := endpoint{uuid: "12345778-1234-abcd-ef00-0123456789ac", version: "1.0", binding: "ncacn_ip_tcp:10.0.0.5[49999]"}

	created, deleted := diffSnapshots(set(oldEp), set(newEp))
	if len(created) != 1 || created[0].binding != newEp.binding {
		t.Fatalf("created = %+v, want the new binding", created)
	}
	if len(deleted) != 1 || deleted[0].binding != oldEp.binding {
		t.Fatalf("deleted = %+v, want the old binding", deleted)
	}
}
