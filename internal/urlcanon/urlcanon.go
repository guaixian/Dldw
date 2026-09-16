// Package urlcanon canonicalizes URLs and derives cache keys and artifact
// families. It is shared by client and server so both sides compute identical
// cache keys for the same URL.
package urlcanon

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Artifact families. Only URLs that map to a family are considered cacheable
// static artifacts (see spec 4.3).
const (
	FamilyGithubRelease = "github-release"
	FamilyPyPIFile      = "pypi-file"
	FamilyNpmTarball    = "npm-tarball"
	FamilyDockerBlob    = "docker-blob"
	FamilyGenericStatic = "generic-static"
)

// Canonicalize normalizes a URL for caching purposes:
//   - scheme and host lowercased
//   - trailing dot removed from host
//   - default port for scheme removed (http:80, https:443)
//   - fragment and userinfo removed (they must not affect the artifact)
//   - path and query preserved verbatim
func Canonicalize(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("empty url")
	}
	if len(raw) > 8192 {
		return "", fmt.Errorf("url too long (%d bytes)", len(raw))
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid url: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("unsupported scheme %q (want http/https)", u.Scheme)
	}
	host := u.Hostname() // strips brackets
	if host == "" {
		return "", fmt.Errorf("missing host")
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if strings.ContainsAny(host, " \t\r\n") {
		return "", fmt.Errorf("invalid host")
	}
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		p, err := net.LookupPort("tcp", port)
		if err != nil || p <= 0 || p > 65535 {
			return "", fmt.Errorf("invalid port %q", port)
		}
		host = net.JoinHostPort(host, port) // brackets IPv6 automatically
	} else if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]" // bare IPv6 literal
	}
	var b strings.Builder
	b.WriteString(scheme)
	b.WriteString("://")
	b.WriteString(host)
	if u.Path == "" {
		b.WriteString("/")
	} else {
		b.WriteString(u.Path)
	}
	if u.RawQuery != "" {
		b.WriteString("?")
		b.WriteString(u.RawQuery)
	}
	return b.String(), nil
}

// HostPort extracts host and port from canonical URL.
func HostPort(canonical string) (host string, port string, err error) {
	u, err := url.Parse(canonical)
	if err != nil {
		return "", "", err
	}
	h := u.Hostname()
	p := u.Port()
	if p == "" {
		if u.Scheme == "https" {
			p = "443"
		} else {
			p = "80"
		}
	}
	return h, p, nil
}

// CacheKey derives the content addressed cache key from a canonical URL and
// its artifact family: hex(sha256(family + "\n" + canonical_url)).
func CacheKey(canonicalURL, family string) string {
	h := sha256.New()
	h.Write([]byte(family))
	h.Write([]byte("\n"))
	h.Write([]byte(canonicalURL))
	return hex.EncodeToString(h.Sum(nil))
}

var staticExts = []string{
	".zip", ".tar", ".tgz", ".gz", ".xz", ".bz2", ".7z", ".zst", ".br",
	".whl", ".jar", ".war", ".deb", ".rpm", ".apk", ".iso", ".img",
	".dmg", ".pkg", ".exe", ".msi", ".bin", ".ova", ".vhd", ".sqsh",
	".gem", ".nupkg", ".AppImage", ".snap",
}

// ClassifyFamily maps a URL to an artifact family. It returns "" when the URL
// does not look like a cacheable static artifact.
func ClassifyFamily(u *url.URL) string {
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	path := u.Path

	switch {
	case host == "github.com":
		if strings.Contains(path, "/releases/download/") || strings.Contains(path, "/archive/") {
			return FamilyGithubRelease
		}
	case host == "objects.githubusercontent.com" || host == "codeload.github.com" ||
		strings.HasSuffix(host, ".releases.githubusercontent.com"):
		return FamilyGithubRelease
	case host == "files.pythonhosted.org" || host == "pypi.org":
		return FamilyPyPIFile
	case host == "registry.npmjs.org" || strings.HasSuffix(host, ".npmjs.org"):
		return FamilyNpmTarball
	case host == "registry-1.docker.io" || host == "registry.docker.io" ||
		host == "production.cloudflare.docker.com" || strings.HasSuffix(host, ".docker.io"):
		return FamilyDockerBlob
	}

	lower := strings.ToLower(path)
	for _, ext := range staticExts {
		if strings.HasSuffix(lower, ext) {
			return FamilyGenericStatic
		}
	}
	return ""
}

// FamilyOfRaw canonicalizes raw and returns (canonical, family, cacheKey).
// family is "" when the URL is not a recognized cacheable static artifact.
func FamilyOfRaw(raw string) (canonical, family, cacheKey string, err error) {
	canonical, err = Canonicalize(raw)
	if err != nil {
		return "", "", "", err
	}
	u, err := url.Parse(canonical)
	if err != nil {
		return "", "", "", err
	}
	family = ClassifyFamily(u)
	if family == "" {
		return canonical, "", "", nil
	}
	return canonical, family, CacheKey(canonical, family), nil
}
