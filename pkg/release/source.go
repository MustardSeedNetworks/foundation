// SPDX-License-Identifier: BUSL-1.1

package release

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/semver"
)

// maxAssetBytes bounds any single download, so a hostile source cannot fill
// the disk. The largest fleet artifact today is under 100 MB.
const maxAssetBytes = 1 << 30

// Source is where releases come from. Every source uses one layout,
// <base>/<tag>/<asset>, with assets under their release names. A source is
// not trusted: it can withhold a release, but Verify refuses anything it
// alters.
type Source interface {
	// Latest returns the newest release tag the source publishes.
	Latest(ctx context.Context) (string, error)
	// Open returns the named asset of release tag.
	Open(ctx context.Context, tag, asset string) (io.ReadCloser, error)
}

// ParseSource resolves an operator's source setting:
//
//   - "github" is the GitHub releases of repository (owner/name);
//   - an https:// URL is a mirror, which names its newest tag in <base>/latest
//     because HTTPS has no portable directory listing;
//   - an absolute directory path is an air-gapped drop, whose newest release
//     is its highest vMAJOR.MINOR.PATCH subdirectory.
func ParseSource(spec, repository string, client *http.Client) (Source, error) {
	switch {
	case spec == "github":
		return &httpSource{
			client:    client,
			base:      "https://github.com/" + repository + "/releases/download",
			latestURL: "https://api.github.com/repos/" + repository + "/releases/latest",
			githubAPI: true,
		}, nil
	case strings.HasPrefix(spec, "https://"):
		base := strings.TrimRight(spec, "/")
		return &httpSource{client: client, base: base, latestURL: base + "/latest"}, nil
	case filepath.IsAbs(spec):
		return dirSource(filepath.Clean(spec)), nil
	default:
		return nil, fmt.Errorf("release: source %q is not \"github\", an https:// URL or an absolute directory", spec)
	}
}

type httpSource struct {
	client    *http.Client
	base      string
	latestURL string
	githubAPI bool
}

func (s *httpSource) Latest(ctx context.Context) (string, error) {
	body, err := s.get(ctx, s.latestURL)
	if err != nil {
		return "", err
	}
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, maxMetadataBytes))
	if err != nil {
		return "", fmt.Errorf("release: read %s: %w", s.latestURL, err)
	}
	tag := strings.TrimSpace(string(data))
	if s.githubAPI {
		var rel struct {
			TagName string `json:"tag_name"`
		}
		if err := json.Unmarshal(data, &rel); err != nil {
			return "", fmt.Errorf("release: decode %s: %w", s.latestURL, err)
		}
		tag = rel.TagName
	}
	if err := checkTag(tag); err != nil {
		return "", err
	}
	return tag, nil
}

func (s *httpSource) Open(ctx context.Context, tag, asset string) (io.ReadCloser, error) {
	if err := checkTag(tag); err != nil {
		return nil, err
	}
	if err := checkAssetName(asset); err != nil {
		return nil, err
	}
	return s.get(ctx, s.base+"/"+tag+"/"+asset)
}

func (s *httpSource) get(ctx context.Context, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("release: %w", err)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("release: GET %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("release: GET %s: %s", url, resp.Status)
	}
	return resp.Body, nil
}

type dirSource string

func (d dirSource) Latest(context.Context) (string, error) {
	entries, err := os.ReadDir(string(d))
	if err != nil {
		return "", fmt.Errorf("release: %w", err)
	}
	latest := ""
	for _, e := range entries {
		if e.IsDir() && tagPattern.MatchString(e.Name()) && (latest == "" || semver.Compare(e.Name(), latest) > 0) {
			latest = e.Name()
		}
	}
	if latest == "" {
		return "", fmt.Errorf("release: %s holds no vMAJOR.MINOR.PATCH release directory", string(d))
	}
	return latest, nil
}

func (d dirSource) Open(_ context.Context, tag, asset string) (io.ReadCloser, error) {
	if err := checkTag(tag); err != nil {
		return nil, err
	}
	if err := checkAssetName(asset); err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(string(d), tag, asset))
	if err != nil {
		return nil, fmt.Errorf("release: %w", err)
	}
	return f, nil
}

// Fetch copies asset of release tag, and every file that proves it, from src
// into dir, then verifies it. dir should be empty and writable only by the
// caller. It returns the verified asset's path; on any error the asset must
// not be installed.
func (v *Verifier) Fetch(ctx context.Context, src Source, tag, asset, dir string) (string, error) {
	if err := checkTag(tag); err != nil {
		return "", err
	}
	if err := checkAssetName(asset); err != nil {
		return "", err
	}
	for _, name := range []string{asset, asset + bundleSuffix, ChecksumsAsset, ChecksumsAsset + bundleSuffix, v.policy.ProvenanceAsset} {
		if err := download(ctx, src, tag, name, filepath.Join(dir, name)); err != nil {
			return "", err
		}
	}
	if err := v.Verify(tag, dir, asset); err != nil {
		return "", err
	}
	return filepath.Join(dir, asset), nil
}

func download(ctx context.Context, src Source, tag, name, path string) (err error) {
	body, err := src.Open(ctx, tag, name)
	if err != nil {
		return err
	}
	defer body.Close()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("release: %w", err)
	}
	defer func() {
		if cerr := f.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("release: %w", cerr)
		}
	}()
	n, err := io.Copy(f, io.LimitReader(body, maxAssetBytes+1))
	if err != nil {
		return fmt.Errorf("release: download %s: %w", name, err)
	}
	if n > maxAssetBytes {
		return fmt.Errorf("%w: %s exceeds %d bytes", ErrVerification, name, maxAssetBytes)
	}
	return nil
}
