package handler

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go-backend/internal/store/repo"
)

const testReleaseAtomFeed = `<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <title>3.0.1</title>
    <updated>2026-07-19T12:00:00Z</updated>
    <link rel="alternate" href="https://github.com/EchoHS/flvx/releases/tag/3.0.1"/>
  </entry>
  <entry>
    <title>3.0.0-beta1</title>
    <updated>2026-07-18T12:00:00Z</updated>
    <link rel="alternate" href="https://github.com/EchoHS/flvx/releases/tag/3.0.0-beta1"/>
  </entry>
</feed>`

func testHTTPResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestFetchGitHubReleasesAtomParsesReleaseTags(t *testing.T) {
	originalGet := githubHTTPGet
	t.Cleanup(func() { githubHTTPGet = originalGet })

	var gotURL string
	githubHTTPGet = func(client *http.Client, url string) (*http.Response, error) {
		gotURL = url
		return testHTTPResponse(http.StatusOK, testReleaseAtomFeed), nil
	}

	got, err := fetchGitHubReleasesAtom("https://proxy.example.com/https://github.com/EchoHS/flvx/releases.atom", 50)
	if err != nil {
		t.Fatalf("fetchGitHubReleasesAtom() error = %v", err)
	}
	if gotURL != "https://proxy.example.com/https://github.com/EchoHS/flvx/releases.atom" {
		t.Fatalf("feed URL = %q", gotURL)
	}
	if len(got) != 2 {
		t.Fatalf("release count = %d, want 2", len(got))
	}
	if got[0].TagName != "3.0.1" || got[0].PublishedAt != "2026-07-19T12:00:00Z" {
		t.Fatalf("first release = %#v", got[0])
	}
	if got[1].TagName != "3.0.0-beta1" {
		t.Fatalf("second release tag = %q", got[1].TagName)
	}
}

func TestHandlerFetchGitHubReleasesUsesProxyFeed(t *testing.T) {
	repoStore, err := repo.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("repo.Open() error = %v", err)
	}
	defer repoStore.Close()

	if err := repoStore.UpsertConfig("github_proxy_enabled", "true", 1); err != nil {
		t.Fatalf("enable proxy error = %v", err)
	}
	if err := repoStore.UpsertConfig("github_proxy_url", "https://proxy.example.com/", 1); err != nil {
		t.Fatalf("proxy URL error = %v", err)
	}

	originalGet := githubHTTPGet
	t.Cleanup(func() { githubHTTPGet = originalGet })
	var gotURLs []string
	githubHTTPGet = func(client *http.Client, url string) (*http.Response, error) {
		gotURLs = append(gotURLs, url)
		return testHTTPResponse(http.StatusOK, testReleaseAtomFeed), nil
	}

	h := &Handler{repo: repoStore}
	got, err := h.fetchGitHubReleases(50)
	if err != nil {
		t.Fatalf("fetchGitHubReleases() error = %v", err)
	}
	if len(got) != 2 || got[0].TagName != "3.0.1" {
		t.Fatalf("releases = %#v", got)
	}
	wantURL := "https://proxy.example.com/https://github.com/EchoHS/flvx/releases.atom"
	if len(gotURLs) != 1 || gotURLs[0] != wantURL {
		t.Fatalf("proxy requests = %#v, want [%q]", gotURLs, wantURL)
	}
}

func TestHandlerFetchGitHubReleasesFallsBackToDirectFeed(t *testing.T) {
	repoStore, err := repo.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("repo.Open() error = %v", err)
	}
	defer repoStore.Close()

	if err := repoStore.UpsertConfig("github_proxy_enabled", "true", 1); err != nil {
		t.Fatalf("enable proxy error = %v", err)
	}
	if err := repoStore.UpsertConfig("github_proxy_url", "https://proxy.example.com", 1); err != nil {
		t.Fatalf("proxy URL error = %v", err)
	}

	originalGet := githubHTTPGet
	t.Cleanup(func() { githubHTTPGet = originalGet })
	var gotURLs []string
	githubHTTPGet = func(client *http.Client, url string) (*http.Response, error) {
		gotURLs = append(gotURLs, url)
		if strings.HasPrefix(url, "https://proxy.example.com/") {
			return testHTTPResponse(http.StatusBadGateway, "proxy unavailable"), nil
		}
		return testHTTPResponse(http.StatusOK, testReleaseAtomFeed), nil
	}

	h := &Handler{repo: repoStore}
	got, err := h.fetchGitHubReleases(50)
	if err != nil {
		t.Fatalf("fetchGitHubReleases() error = %v", err)
	}
	if len(got) != 2 || got[0].TagName != "3.0.1" {
		t.Fatalf("releases = %#v", got)
	}
	if len(gotURLs) != 2 || gotURLs[0] != "https://proxy.example.com/https://github.com/EchoHS/flvx/releases.atom" || gotURLs[1] != "https://github.com/EchoHS/flvx/releases.atom" {
		t.Fatalf("requests = %#v", gotURLs)
	}
}

func TestHandlerFetchGitHubReleasesUsesDirectFeedWhenProxyDisabled(t *testing.T) {
	repoStore, err := repo.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("repo.Open() error = %v", err)
	}
	defer repoStore.Close()

	if err := repoStore.UpsertConfig("github_proxy_enabled", "false", 1); err != nil {
		t.Fatalf("disable proxy error = %v", err)
	}

	originalGet := githubHTTPGet
	t.Cleanup(func() { githubHTTPGet = originalGet })
	var gotURLs []string
	githubHTTPGet = func(client *http.Client, url string) (*http.Response, error) {
		gotURLs = append(gotURLs, url)
		return testHTTPResponse(http.StatusOK, testReleaseAtomFeed), nil
	}

	h := &Handler{repo: repoStore}
	got, err := h.fetchGitHubReleases(50)
	if err != nil {
		t.Fatalf("fetchGitHubReleases() error = %v", err)
	}
	if len(got) != 2 || got[1].TagName != "3.0.0-beta1" {
		t.Fatalf("releases = %#v", got)
	}
	if len(gotURLs) != 1 || gotURLs[0] != "https://github.com/EchoHS/flvx/releases.atom" {
		t.Fatalf("requests = %#v", gotURLs)
	}
}

func TestListReleasesUsesCurrentPanelVersionWithoutNetwork(t *testing.T) {
	t.Setenv("FLUX_VERSION", "3.0.1-beta2")
	originalGet := githubHTTPGet
	t.Cleanup(func() { githubHTTPGet = originalGet })
	githubHTTPGet = func(client *http.Client, url string) (*http.Response, error) {
		t.Fatal("did not expect a GitHub request for the current panel channel")
		return nil, nil
	}

	h := &Handler{}
	req := httptest.NewRequest(http.MethodPost, "/node/releases", strings.NewReader(`{"channel":"dev"}`))
	recorder := httptest.NewRecorder()
	h.listReleases(recorder, req)

	body := recorder.Body.String()
	if !strings.Contains(body, `"version":"3.0.1-beta2"`) || !strings.Contains(body, `"channel":"dev"`) {
		t.Fatalf("response = %s", body)
	}
}

func TestHandlerFetchGitHubReleasesFallsBackToDirectAPI(t *testing.T) {
	repoStore, err := repo.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("repo.Open() error = %v", err)
	}
	defer repoStore.Close()

	if err := repoStore.UpsertConfig("github_proxy_enabled", "true", 1); err != nil {
		t.Fatalf("enable proxy error = %v", err)
	}
	if err := repoStore.UpsertConfig("github_proxy_url", "https://proxy.example.com", 1); err != nil {
		t.Fatalf("proxy URL error = %v", err)
	}

	originalGet := githubHTTPGet
	t.Cleanup(func() { githubHTTPGet = originalGet })
	var gotURLs []string
	githubHTTPGet = func(client *http.Client, url string) (*http.Response, error) {
		gotURLs = append(gotURLs, url)
		if strings.HasSuffix(url, "/releases.atom") {
			return testHTTPResponse(http.StatusBadGateway, "feed unavailable"), nil
		}
		return testHTTPResponse(http.StatusOK, `[{"tag_name":"3.0.1-beta1","name":"3.0.1-beta1","published_at":"2026-07-22T12:00:00Z"}]`), nil
	}

	h := &Handler{repo: repoStore}
	got, err := h.fetchGitHubReleases(50)
	if err != nil {
		t.Fatalf("fetchGitHubReleases() error = %v", err)
	}
	if len(got) != 1 || got[0].TagName != "3.0.1-beta1" {
		t.Fatalf("releases = %#v", got)
	}
	if len(gotURLs) != 3 || gotURLs[2] != "https://api.github.com/repos/EchoHS/flvx/releases?per_page=50" {
		t.Fatalf("requests = %#v", gotURLs)
	}
}
