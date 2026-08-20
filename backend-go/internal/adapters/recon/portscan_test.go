package recon

import (
	"reflect"
	"testing"
)

const nmapXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/></port>
      <port protocol="tcp" portid="443"><state state="open"/></port>
      <port protocol="tcp" portid="8080"><state state="closed"/></port>
      <port protocol="udp" portid="53"><state state="open"/></port>
    </ports>
  </host>
  <host>
    <address addr="10.0.0.9" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="22"><state state="open"/></port></ports>
  </host>
</nmaprun>`

func TestParseNmapXML_openTCPOnly(t *testing.T) {
	parsed := ParseNmapXML(nmapXML)
	if !reflect.DeepEqual(parsed["93.184.216.34"], []int{80, 443}) { // closed 8080 и udp 53 отброшены
		t.Errorf("93.184.216.34 = %v, want [80 443]", parsed["93.184.216.34"])
	}
	if !reflect.DeepEqual(parsed["10.0.0.9"], []int{22}) {
		t.Errorf("10.0.0.9 = %v, want [22]", parsed["10.0.0.9"])
	}
}

func TestParseNmapXML_garbage(t *testing.T) {
	if got := ParseNmapXML(""); len(got) != 0 {
		t.Errorf("empty XML should be {}, got %v", got)
	}
	if got := ParseNmapXML("<broken"); len(got) != 0 {
		t.Errorf("broken XML should be {}, got %v", got)
	}
}
