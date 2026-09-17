package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dldw/internal/server/auth"
)

// TestMirrorAuthMiddleware 验证镜像端点鉴权：Bearer / Basic（用户名或密码为
// token）通过，缺失或错误令牌 401。
func TestMirrorAuthMiddleware(t *testing.T) {
	tokens, err := auth.NewStore(filepath.Join(t.TempDir(), "tokens.json"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, tok, err := tokens.Register("dev_t")
	if err != nil {
		t.Fatal(err)
	}

	cfg := &Config{Tokens: tokens}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("mirror-content"))
	})
	h := cfg.mirrorAuth(inner)
	srv := httptest.NewServer(h)
	defer srv.Close()

	// 无凭证 -> 401
	resp, _ := http.Get(srv.URL + "/pypi/simple/six/")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no creds: %d", resp.StatusCode)
	}
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Fatal("WWW-Authenticate missing")
	}

	// Bearer -> 200
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/pypi/simple/six/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("bearer: %d", resp2.StatusCode)
	}

	// Basic 用户名=token -> 200（pip/uv 把令牌写在 URL userinfo）
	req3, _ := http.NewRequest(http.MethodGet, srv.URL+"/x", nil)
	req3.SetBasicAuth(tok, "")
	resp3, _ := http.DefaultClient.Do(req3)
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("basic username=token: %d", resp3.StatusCode)
	}

	// Basic 密码=token -> 200
	req4, _ := http.NewRequest(http.MethodGet, srv.URL+"/x", nil)
	req4.SetBasicAuth("anything", tok)
	resp4, _ := http.DefaultClient.Do(req4)
	resp4.Body.Close()
	if resp4.StatusCode != http.StatusOK {
		t.Fatalf("basic password=token: %d", resp4.StatusCode)
	}

	// 错误令牌 -> 401
	req5, _ := http.NewRequest(http.MethodGet, srv.URL+"/x", nil)
	req5.Header.Set("Authorization", "Bearer dldw_wrong")
	resp5, _ := http.DefaultClient.Do(req5)
	resp5.Body.Close()
	if resp5.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", resp5.StatusCode)
	}
	_ = strings.TrimSpace
}
