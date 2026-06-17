package mode_dump

import (
	"net"
	"testing"

	"github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/e1af8308-5d1f-11c9-91a4-08002b14a0fa/3.0/structures"
	"github.com/TheManticoreProject/Manticore/windows/guid"
)

// samrUUID and srvsvcUUID are well-known interfaces present in the framework catalog;
// the tests use them to exercise both UUID extraction and catalog resolution.
const (
	samrUUID   = "12345778-1234-abcd-ef00-0123456789ac"
	srvsvcUUID = "4b324fc8-1670-01d3-1278-5a47bf6ee188"
)

// tcpEntry builds an endpoint-map entry for ifaceUUID v(major.minor) bound over
// ncacn_ip_tcp at the given IP and port, with an optional annotation.
func tcpEntry(t *testing.T, ifaceUUID string, major, minor uint16, ip string, port uint16, annotation string) structures.EptEntry {
	t.Helper()
	g, err := guid.FromString(ifaceUUID)
	if err != nil {
		t.Fatalf("parsing %q: %s", ifaceUUID, err)
	}
	tower := structures.Tower{Floors: []structures.Floor{
		structures.InterfaceFloor(*g, major, minor),
		structures.TransferSyntaxFloor(),
		structures.TCPFloor(port),
		structures.IPFloor(net.ParseIP(ip)),
	}}
	twr := structures.NewTwr(tower)
	return structures.EptEntry{Tower: &twr, Annotation: structures.Annotation(annotation)}
}

func TestInterfaceIDExtractsUUIDAndVersion(t *testing.T) {
	e := tcpEntry(t, samrUUID, 1, 0, "10.0.0.5", 49664, "")
	tower, err := e.DecodeTower()
	if err != nil {
		t.Fatalf("decoding tower: %s", err)
	}

	id, major, minor, ok := interfaceID(tower)
	if !ok {
		t.Fatal("expected an interface-identifier floor")
	}
	if got := id.ToFormatD(); got != samrUUID {
		t.Errorf("uuid = %q, want %q", got, samrUUID)
	}
	if major != 1 || minor != 0 {
		t.Errorf("version = %d.%d, want 1.0", major, minor)
	}
}

func TestGroupFoldsBindingsAndResolvesName(t *testing.T) {
	entries := []structures.EptEntry{
		tcpEntry(t, samrUUID, 1, 0, "10.0.0.5", 49664, "first"),
		tcpEntry(t, samrUUID, 1, 0, "10.0.0.5", 49665, "second"),
		tcpEntry(t, srvsvcUUID, 3, 0, "10.0.0.5", 49152, ""),
	}

	got := group(entries, "", false)
	if len(got) != 2 {
		t.Fatalf("interface count = %d, want 2", len(got))
	}

	// Both interfaces are in the catalog, so they sort by name: samr before srvsvc.
	samr := got[0]
	if samr.Name != "samr" {
		t.Errorf("first interface name = %q, want %q", samr.Name, "samr")
	}
	if samr.Protocol != "MS-SAMR" {
		t.Errorf("samr protocol = %q, want %q", samr.Protocol, "MS-SAMR")
	}
	if len(samr.Bindings) != 2 {
		t.Fatalf("samr bindings = %d, want 2 (folded under one interface)", len(samr.Bindings))
	}
	if samr.Bindings[0].StringBinding != "ncacn_ip_tcp:10.0.0.5[49664]" {
		t.Errorf("samr first binding = %q", samr.Bindings[0].StringBinding)
	}
	if samr.Bindings[0].Annotation != "first" {
		t.Errorf("samr first annotation = %q, want %q", samr.Bindings[0].Annotation, "first")
	}
}

func TestGroupFilterKeepsOnlyMatches(t *testing.T) {
	entries := []structures.EptEntry{
		tcpEntry(t, samrUUID, 1, 0, "10.0.0.5", 49664, ""),
		tcpEntry(t, srvsvcUUID, 3, 0, "10.0.0.5", 49152, ""),
	}

	// Filter by name.
	got := group(entries, "srvsvc", false)
	if len(got) != 1 || got[0].Name != "srvsvc" {
		t.Fatalf("filter 'srvsvc' = %+v, want only srvsvc", got)
	}

	// Filter by protocol (case-insensitive).
	got = group(entries, "ms-samr", false)
	if len(got) != 1 || got[0].Name != "samr" {
		t.Fatalf("filter 'ms-samr' = %+v, want only samr", got)
	}

	// Filter with no match drops everything.
	if got = group(entries, "nonexistent", false); len(got) != 0 {
		t.Fatalf("filter 'nonexistent' = %+v, want empty", got)
	}
}

func TestGroupSkipsEntriesWithoutTower(t *testing.T) {
	entries := []structures.EptEntry{
		{Tower: nil, Annotation: "no tower"},
		tcpEntry(t, samrUUID, 1, 0, "10.0.0.5", 49664, ""),
	}
	got := group(entries, "", false)
	if len(got) != 1 {
		t.Fatalf("interface count = %d, want 1 (null-tower entry skipped)", len(got))
	}
}
