// SPDX-License-Identifier: BUSL-1.1

package release

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSource(t *testing.T) {
	const repo = "MustardSeedNetworks/stem"
	gh, err := ParseSource("github", repo, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	hs := gh.(*httpSource)
	if hs.base != "https://github.com/"+repo+"/releases/download" || hs.latestURL != "https://api.github.com/repos/"+repo+"/releases/latest" || !hs.githubAPI {
		t.Errorf("github source = %+v", hs)
	}

	mirror, err := ParseSource("https://mirror.example/stem/", repo, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	if ms := mirror.(*httpSource); ms.base != "https://mirror.example/stem" || ms.latestURL != "https://mirror.example/stem/latest" || ms.githubAPI {
		t.Errorf("mirror source = %+v", ms)
	}

	root := t.TempDir()
	sep := string(filepath.Separator)
	dir, err := ParseSource(root+sep+"stem"+sep+".."+sep+"stem-releases", repo, nil)
	if err != nil {
		t.Fatal(err)
	}
	if dir != dirSource(filepath.Join(root, "stem-releases")) {
		t.Errorf("dir source = %q", dir)
	}

	for _, bad := range []string{"", "GitHub", "http://mirror.example/stem", "releases/stem", "ftp://mirror.example"} {
		if _, err := ParseSource(bad, repo, http.DefaultClient); err == nil {
			t.Errorf("ParseSource(%q) = nil error, want a refusal", bad)
		}
	}
}

func TestDirSourceLatest(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"v0.9.0", "v0.10.2", "v0.10.10", "v1.0.0-rc1", "latest", "v2.0"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// A file named like a newer release is not a release directory.
	if err := os.WriteFile(filepath.Join(root, "v9.0.0"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := dirSource(root).Latest(t.Context())
	if err != nil || got != "v0.10.10" {
		t.Fatalf("Latest = %q, %v; want v0.10.10", got, err)
	}
	if _, err := dirSource(t.TempDir()).Latest(t.Context()); err == nil {
		t.Fatal("Latest of an empty drop = nil error")
	}
}

func TestHTTPSourceLatest(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		githubAPI bool
		want      string
	}{
		{name: "mirror file", body: "v0.27.14\n", want: "v0.27.14"},
		{name: "github api", body: `{"tag_name":"v0.27.14","name":"v0.27.14"}`, githubAPI: true, want: "v0.27.14"},
		{name: "mirror names no tag", body: "../../etc\n"},
		{name: "github api prerelease tag", body: `{"tag_name":"v0.28.0-rc1"}`, githubAPI: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, tt.body)
			}))
			defer srv.Close()
			s := &httpSource{client: srv.Client(), base: srv.URL, latestURL: srv.URL + "/latest", githubAPI: tt.githubAPI}
			got, err := s.Latest(t.Context())
			if tt.want == "" {
				if err == nil {
					t.Fatalf("Latest = %q, want a refusal", got)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Fatalf("Latest = %q, %v; want %q", got, err, tt.want)
			}
		})
	}
}

// mirror serves testdata under the release layout, as an operator's HTTPS
// mirror would, with an artifact the caller chooses.
func mirror(t *testing.T, artifact []byte) Source {
	t.Helper()
	files := http.StripPrefix("/stem", http.FileServer(http.Dir("testdata")))
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stem/"+fixtureTag+"/"+fixtureDeb && artifact != nil {
			_, _ = w.Write(artifact)
			return
		}
		files.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	src, err := ParseSource(srv.URL+"/stem", "", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	return src
}

func TestFetchRefusesTamperedArtifact(t *testing.T) {
	dir := t.TempDir()
	_, err := mustVerifier(t, stemPolicy()).Fetch(t.Context(), mirror(t, []byte("not the release")), fixtureTag, fixtureDeb, dir)
	if !errors.Is(err, ErrVerification) || !strings.Contains(err.Error(), "does not match checksums.txt") {
		t.Fatalf("Fetch = %v, want a checksum refusal", err)
	}
	// Every proving file was fetched beside the artifact.
	for _, name := range []string{fixtureDeb + bundleSuffix, ChecksumsAsset, ChecksumsAsset + bundleSuffix, stemPolicy().ProvenanceAsset} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("Fetch did not stage %s: %v", name, err)
		}
	}
}

func TestFetchFailsOnMissingAsset(t *testing.T) {
	_, err := mustVerifier(t, stemPolicy()).Fetch(t.Context(), mirror(t, nil), fixtureTag, fixtureDeb, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("Fetch of an unpublished artifact = %v, want the 404", err)
	}
}

func TestFetchRefusesPreexistingFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, fixtureDeb), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := mustVerifier(t, stemPolicy()).Fetch(t.Context(), mirror(t, []byte("x")), fixtureTag, fixtureDeb, dir); !errors.Is(err, os.ErrExist) {
		t.Fatalf("Fetch into a dirty directory = %v, want os.ErrExist", err)
	}
}
