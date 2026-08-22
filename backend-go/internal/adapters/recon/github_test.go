package recon

import "testing"

// ParseGithubTarget: один сегмент → org/user (--org), два → репозиторий (--repo).
func TestParseGithubTarget(t *testing.T) {
	repo, err := ParseGithubTarget("https://github.com/owner/repo")
	if err != nil {
		t.Fatalf("repo: %v", err)
	}
	if repo.IsOrg || repo.Repo != "https://github.com/owner/repo" {
		t.Fatalf("unexpected repo target: %+v", repo)
	}
	// .git-хвост нормализуется
	if got, _ := ParseGithubTarget("https://github.com/owner/repo.git"); got.Repo != "https://github.com/owner/repo" {
		t.Fatalf("git suffix not trimmed: %+v", got)
	}

	org, err := ParseGithubTarget("https://github.com/acme")
	if err != nil {
		t.Fatalf("org: %v", err)
	}
	if !org.IsOrg || org.Org != "acme" {
		t.Fatalf("unexpected org target: %+v", org)
	}

	if _, err := ParseGithubTarget("https://gitlab.com/owner/repo"); err == nil {
		t.Fatal("expected error for non-github host")
	}
	if _, err := ParseGithubTarget("https://github.com/"); err == nil {
		t.Fatal("expected error for empty path")
	}
}

// parseGithubOutput разбирает построчный JSON trufflehog github в находки,
// вытаскивая поля SourceMetadata.Data.Github.
func TestParseGithubOutput(t *testing.T) {
	out := `{"DetectorName":"AWS","Verified":true,"Raw":"AKIA","SourceMetadata":{"Data":{"Github":{"repository":"https://github.com/o/r","file":"a.yml","link":"https://github.com/o/r/blob/x/a.yml","commit":"abc"}}}}
garbage line
{"DetectorName":"","Raw":"skip"}
{"DetectorName":"Generic","Verified":false,"Raw":"tok","SourceMetadata":{"Data":{"Github":{"repository":"https://github.com/o/r","file":"b.js"}}}}`
	got := parseGithubOutput([]byte(out))
	if len(got) != 2 {
		t.Fatalf("expected 2 parsed, got %d: %+v", len(got), got)
	}
	if got[0].Detector != "AWS" || !got[0].Verified || got[0].Raw != "AKIA" || got[0].Repo != "https://github.com/o/r" || got[0].File != "a.yml" || got[0].Commit != "abc" {
		t.Fatalf("first finding wrong: %+v", got[0])
	}
	if got[1].Detector != "Generic" || got[1].Verified {
		t.Fatalf("second finding wrong: %+v", got[1])
	}
}
