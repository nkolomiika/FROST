package report

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestTemplateRoundTrip(t *testing.T) {
	for _, kind := range []Kind{KindSZI, KindPP} {
		d, err := LoadTemplate(kind)
		if err != nil {
			t.Fatalf("%s load: %v", kind, err)
		}
		// touch document.xml through etree so Save re-serializes it
		if _, err := d.Document(); err != nil {
			t.Fatalf("%s document: %v", kind, err)
		}
		out, err := d.Save()
		if err != nil {
			t.Fatalf("%s save: %v", kind, err)
		}
		// re-open and verify it's a valid zip containing document.xml with markers intact
		zr, err := zip.NewReader(bytes.NewReader(out), int64(len(out)))
		if err != nil {
			t.Fatalf("%s reopen zip: %v", kind, err)
		}
		var docXML string
		names := map[string]bool{}
		for _, f := range zr.File {
			names[f.Name] = true
			if f.Name == "word/document.xml" {
				rc, _ := f.Open()
				b, _ := io.ReadAll(rc)
				rc.Close()
				docXML = string(b)
			}
		}
		for _, must := range []string{"[Content_Types].xml", "word/document.xml", "word/styles.xml", "word/settings.xml"} {
			if !names[must] {
				t.Fatalf("%s: missing part %s after save", kind, must)
			}
		}
		// structural markers preserved (example card, placeholders, Word fields)
		for _, marker := range []string{"XXX", "fldChar", "instrText"} {
			if !strings.Contains(docXML, marker) {
				t.Fatalf("%s: marker %q lost in round-trip", kind, marker)
			}
		}
		if strings.Count(docXML, "<w:") < 1000 {
			t.Fatalf("%s: document.xml looks truncated (%d w: tags)", kind, strings.Count(docXML, "<w:"))
		}
	}
}
