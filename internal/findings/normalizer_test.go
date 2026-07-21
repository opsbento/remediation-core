package findings

import "testing"

func TestNormalizeGrypeFiltersSeverity(t *testing.T) {
	raw := []byte(`{
	  "matches": [
	    {
	      "vulnerability": {"id":"CVE-1","severity":"High","fix":{"state":"fixed","versions":["1.0.1"]}},
	      "artifact": {"name":"pkg","version":"1.0.0","type":"npm","language":"npm"}
	    },
	    {
	      "vulnerability": {"id":"CVE-2","severity":"Low","fix":{"state":"fixed","versions":["1.0.2"]}},
	      "artifact": {"name":"pkg","version":"1.0.0","type":"npm","language":"npm"}
	    }
	  ]
	}`)

	got, err := NormalizeGrype(raw, "high")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].VulnerabilityID != "CVE-1" {
		t.Fatalf("unexpected findings: %#v", got)
	}
	if got[0].Ecosystem != "npm" {
		t.Fatalf("got ecosystem %q, want npm", got[0].Ecosystem)
	}
}
