package app

import(
	"bytes"
	"os"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"dldw/internal/ids"
	"dldw/internal/policy/ssrf"
	"dldw/internal/policy/whitelist"
	"dldw/internal/protocol/dldw1"
	"dldw/internal/server/audit"
	"dldw/internal/server/auth"
	"dldw/internal/server/tunnel"
)

// newTestApp spins up the whole server app against a temp dir and an origin
// server reachable via loopback (ports opened accordingly).
func newTestApp(t *testing.T) (*App, string /*apiBase*/, *httptest.Server /*origin*/, string /*token*/) {
	t.Helper()
	dir := t.TempDir()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".tar.gz") {
			w.Header().Set("Content-Type", "application/gzip")
			w.Write(bytes.Repeat([]byte("dldw-artifact!"), 512)) // 8KiB
			return
		}
		w.Write([]byte("hello"))
	}))
	t.Cleanup(origin.Close)

	ou, _ := url.Parse(origin.URL)
	port, _ := strconv.Atoi(ou.Port())

	// allocate free ports for api + tunnel
	apiLn, _ := net.Listen("tcp", "127.0.0.1:0")
	apiLn.Close()
	tunLn, _ := net.Listen("tcp", "127.0.0.1:0")
	tunLn.Close()

	cfg := Default(dir)
	cfg.Listen = apiLn.Addr().String()
	cfg.PublicBase = "http://" + cfg.Listen
	cfg.Tunnel.Listen = tunLn.Addr().String()
	cfg.Executor.Ports = []int{port}
	cfg.Executor.AllowLoopback = true

	app, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// token
	rec, tok, err := app.Tokens.Register("dev_test")
	if err != nil {
		t.Fatal(err)
	}
	_ = rec

	apiSrv := &http.Server{Handler: app.Handler()}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		t.Fatal(err)
	}
	go apiSrv.Serve(ln)
	t.Cleanup(func() { apiSrv.Close() })

	base := "http://" + cfg.Listen

	// tunnel listener
	tln, err := net.Listen("tcp", cfg.Tunnel.Listen)
	if err != nil {
		t.Fatal(err)
	}
	go app.serveTunnelForTest(tln)
	t.Cleanup(func() { tln.Close() })

	return app, base, origin, tok
}

func (a *App) serveTunnelForTest(ln net.Listener) {
	srv := newTestTunnelServer(a)
	srv.Serve(context.Background(), ln)
}

func apiJSON(t *testing.T, method, base, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		buf, _ := json.Marshal(body)
		rdr = bytes.NewReader(buf)
	}
	req, _ := http.NewRequest(method, base+path, rdr)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	buf, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if len(buf) > 0 {
		json.Unmarshal(buf, &out)
	}
	return resp.StatusCode, out
}

func TestHealthAndReady(t *testing.T) {
	_, base, _, _ := newTestApp(t)
	st, body := apiJSON(t, "GET", base, "/healthz", "", nil)
	if st != 200 || body["status"] != "ok" {
		t.Fatalf("healthz: %d %v", st, body)
	}
	st, body = apiJSON(t, "GET", base, "/readyz", "", nil)
	if st != 200 || body["status"] != "ok" {
		t.Fatalf("readyz: %d %v", st, body)
	}
}

func TestResolveAuth(t *testing.T) {
	_, base, _, _ := newTestApp(t)
	st, body := apiJSON(t, "POST", base, "/api/v1/resolve", "bogus", map[string]any{"url": "https://github.com/x/y/releases/download/v1/a.tar.gz"})
	if st != 401 {
		t.Fatalf("expected 401, got %d %v", st, body)
	}
	if e, _ := body["error"].(map[string]any); e["code"] != "E_RESOLVE_AUTH" {
		t.Fatalf("error = %v", body)
	}
	st, _ = apiJSON(t, "POST", base, "/api/v1/resolve", "", nil)
	if st != 401 {
		t.Fatalf("no token: %d", st)
	}
}

func TestResolveE2EWithPresignedDownload(t *testing.T) {
	_, base, origin, tok := newTestApp(t)
	artifact := origin.URL + "/org/repo/releases/download/v1/app.tar.gz"

	// origin is loopback but family classification uses path suffix (.tar.gz)
	st, res := apiJSON(t, "POST", base, "/api/v1/resolve", tok, map[string]any{"url": artifact})
	if st != 200 {
		t.Fatalf("resolve: %d %v", st, res)
	}
	status, _ := res["status"].(string)

	// poll until ready/cached
	deadline := time.Now().Add(10 * time.Second)
	for status != "cached" && status != "ready" && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		taskObj, _ := res["task"].(map[string]any)
		id, _ := taskObj["id"].(string)
		if id == "" {
			t.Fatalf("no task in response: %v", res)
		}
		st, res = apiJSON(t, "GET", base, "/api/v1/tasks/"+id, tok, nil)
		if st != 200 {
			t.Fatalf("task poll: %d %v", st, res)
		}
		taskObj, _ = res["task"].(map[string]any)
		status, _ = taskObj["status"].(string)
	}
	if status != "cached" && status != "ready" {
		t.Fatalf("never cached: %v", res)
	}
	taskID, _ := res["task"].(map[string]any)["id"].(string)

	// refresh gives the full result with presigned download info
	st, res = apiJSON(t, "POST", base, "/api/v1/tasks/"+taskID+"/refresh", tok, nil)
	if st != 200 {
		t.Fatalf("refresh: %d %v", st, res)
	}

	dl, _ := res["download"].(map[string]any)
	urls, _ := dl["urls"].([]any)
	if len(urls) != 1 {
		t.Fatalf("urls: %v", dl)
	}
	if dl["mode"] != "presigned" || dl["supports_range"] != true {
		t.Fatalf("download: %v", dl)
	}
	presigned, _ := urls[0].(string)
	// presigned URL is on our API base
	if !strings.HasPrefix(presigned, base+"/files/") {
		t.Fatalf("presigned url: %q", presigned)
	}

	// full GET
	resp, err := http.Get(presigned)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || len(body) != 7168 {
		t.Fatalf("GET presigned: %d len=%d", resp.StatusCode, len(body))
	}

	// range GET
	req, _ := http.NewRequest("GET", presigned, nil)
	req.Header.Set("Range", "bytes=0-1023")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent || len(body) != 1024 {
		t.Fatalf("range: %d len=%d", resp.StatusCode, len(body))
	}

	// tampered signature
	bad := strings.Split(presigned, "sig=")
	badURL := bad[0] + "sig=deadbeef"
	resp, err = http.Get(badURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("tampered sig: %d", resp.StatusCode)
	}
}

func TestNotCacheable(t *testing.T) {
	_, base, _, tok := newTestApp(t)
	st, res := apiJSON(t, "POST", base, "/api/v1/resolve", tok, map[string]any{"url": "https://example.com/api/whatever"})
	if st != 422 {
		t.Fatalf("want 422, got %d %v", st, res)
	}
}

func TestWhitelistEndpoint(t *testing.T) {
	_, base, _, _ := newTestApp(t)
	st, res := apiJSON(t, "GET", base, "/api/v1/whitelist", "", nil)
	if st != 200 {
		t.Fatalf("whitelist: %d", st)
	}
	entries, _ := res["entries"].([]any)
	if len(entries) == 0 {
		t.Fatal("no entries")
	}
	if res["version"] == "" {
		t.Fatal("no version")
	}
}

func TestIntrospect(t *testing.T) {
	_, base, _, tok := newTestApp(t)
	st, res := apiJSON(t, "POST", base, "/api/v1/introspect", tok, nil)
	if st != 200 || res["ok"] != true {
		t.Fatalf("introspect: %d %v", st, res)
	}
	tk, _ := res["token"].(map[string]any)
	if tk["valid"] != true {
		t.Fatalf("token: %v", tk)
	}
	stor, _ := res["storage"].(map[string]any)
	if stor["ok"] != true {
		t.Fatalf("storage: %v", stor)
	}
}

func TestTokenEndpoint(t *testing.T) {
	_, base, _, _ := newTestApp(t)
	st, res := apiJSON(t, "POST", base, "/api/v1/token", "", map[string]any{"action": "register", "client_id": "dev_x"})
	if st != 201 {
		t.Fatalf("register: %d %v", st, res)
	}
	tok, _ := res["token"].(string)
	if tok == "" {
		t.Fatal("no token issued")
	}
	// refresh
	st, res = apiJSON(t, "POST", base, "/api/v1/token", "", map[string]any{"action": "refresh", "token": tok})
	if st != 200 {
		t.Fatalf("refresh: %d %v", st, res)
	}
	tok2, _ := res["token"].(string)
	// revoke
	st, _ = apiJSON(t, "POST", base, "/api/v1/token", "", map[string]any{"action": "revoke", "token": tok2})
	if st != 200 {
		t.Fatalf("revoke: %d", st)
	}
	st, _ = apiJSON(t, "POST", base, "/api/v1/resolve", tok2, map[string]any{"url": "https://github.com/x/y/releases/download/v1/a.tar.gz"})
	if st != 401 {
		t.Fatalf("revoked token must 401, got %d", st)
	}
}

func TestTunnelNegativeCases(t *testing.T) {
	app, _, _, tok := newTestApp(t)

	dial := func() (net.Conn, *bufReader) {
		conn, err := net.Dial("tcp", app.Cfg.Tunnel.Listen)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		return conn, newBufReader(conn)
	}

	// bad token
	conn, br := dial()
	conn.Write((&dldw1.Connect{Host: "github.com", Port: 443, Token: "bogus_token_123", Nonce: ids.NewNonce(), ClientID: "dev_test"}).Encode())
	line, err := br.readLine()
	if err != nil {
		t.Fatal(err)
	}
	_, errRes, _ := dldw1.ParseResponse(line)
	if errRes == nil || errRes.Code != "E_AUTH" {
		t.Fatalf("want E_AUTH, got %+v", errRes)
	}

	// nonce replay
	nonce := ids.NewNonce()
	conn2, br2 := dial()
	conn2.Write((&dldw1.Connect{Host: "github.com", Port: 443, Token: tok, Nonce: nonce, ClientID: "dev_test"}).Encode())
	line2, _ := br2.readLine()
	if _, e, _ := dldw1.ParseResponse(line2); e != nil && e.Code != "E_AUTH" {
		// first attempt may fail with E_UPSTREAM/DNS but the nonce is still consumed
		_ = e
	}
	conn3, br3 := dial()
	conn3.Write((&dldw1.Connect{Host: "github.com", Port: 443, Token: tok, Nonce: nonce, ClientID: "dev_test"}).Encode())
	line3, _ := br3.readLine()
	_, err3, _ := dldw1.ParseResponse(line3)
	if err3 == nil || err3.Code != "E_REPLAY" {
		t.Fatalf("want E_REPLAY, got %+v", err3)
	}

	// not whitelisted
	conn4, br4 := dial()
	conn4.Write((&dldw1.Connect{Host: "evil.example.com", Port: 443, Token: tok, Nonce: ids.NewNonce(), ClientID: "dev_test"}).Encode())
	line4, _ := br4.readLine()
	_, err4, _ := dldw1.ParseResponse(line4)
	if err4 == nil || err4.Code != "E_NOT_WHITELISTED" {
		t.Fatalf("want E_NOT_WHITELISTED, got %+v", err4)
	}

	// IP literals are never whitelisted
	conn5, br5 := dial()
	conn5.Write((&dldw1.Connect{Host: "127.0.0.1", Port: 443, Token: tok, Nonce: ids.NewNonce(), ClientID: "dev_test"}).Encode())
	line5, _ := br5.readLine()
	_, err5, _ := dldw1.ParseResponse(line5)
	if err5 == nil || err5.Code != "E_NOT_WHITELISTED" {
		t.Fatalf("IP literal should not whitelist: %+v", err5)
	}

	// port denied (whitelisted host, port 22)
	conn6, br6 := dial()
	conn6.Write((&dldw1.Connect{Host: "github.com", Port: 22, Token: tok, Nonce: ids.NewNonce(), ClientID: "dev_test"}).Encode())
	line6, _ := br6.readLine()
	_, err6, _ := dldw1.ParseResponse(line6)
	if err6 == nil || err6.Code != "E_PORT_DENIED" {
		t.Fatalf("want E_PORT_DENIED, got %+v", err6)
	}
}

func TestTunnelHappyPath(t *testing.T) {
	// local echo server as tunnel target
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()
	_, echoPort, _ := net.SplitHostPort(echo.Addr().String())
	port, _ := strconv.Atoi(echoPort)

	// tunnel with loopback allowed + localhost whitelisted (test-only policy)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	dir := t.TempDir()
	cfg := Default(dir)
	cfg.Executor.Ports = []int{port}
	app, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, tok, _ := app.Tokens.Register("dev_tun")
	app.WLStore.Swap(whitelist.Parse("t", []string{"localhost"}))

	srv := tunnel.New(tunnel.Config{
		Tokens:           app.Tokens,
		Nonces:           auth.NewNonceStore(time.Minute),
		WL:               app.WLStore,
		Policy:           &ssrf.Policy{AllowLoopback: true, Ports: []int{port}},
		Audit:            audit.New(nil),
		MaxConnsPerToken: 4,
		MaxBytesPerConn:  1 << 20,
		IdleTimeout:      10 * time.Second,
	})
	go srv.Serve(context.Background(), ln)

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write((&dldw1.Connect{Host: "localhost", Port: port, Token: tok, Nonce: ids.NewNonce(), ClientID: "dev_tun"}).Encode())
	line, err := newBufReader(conn).readLine()
	if err != nil {
		t.Fatal(err)
	}
	okRes, errRes, perr := dldw1.ParseResponse(line)
	if perr != nil {
		t.Fatalf("parse: %v (%q)", perr, line)
	}
	if errRes != nil {
		t.Fatalf("handshake failed: %+v", errRes)
	}
	if !strings.HasPrefix(okRes.ConnID, "conn_") || okRes.ExpiresIn != 10 || okRes.ResolvedIP != "127.0.0.1" {
		t.Fatalf("ok = %+v", okRes)
	}
	// raw TCP echo through the tunnel
	payload := []byte("ping-through-dldw-tunnel")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("echo mismatch: %q", buf)
	}
}

func TestLoadWhitelist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wl.txt")
	content := "# version: v-test\ngithub.com\n \nevil.com\n# comment\n"
	if err := writeWhitelist(path, content); err != nil {
		t.Fatal(err)
	}
	l, err := LoadWhitelist(path)
	if err != nil {
		t.Fatal(err)
	}
	if l.Version() != "v-test" || !l.Match("github.com") || !l.Match("evil.com") || l.Match("x.com") {
		t.Fatalf("whitelist = %s %v", l.Version(), l.Entries())
	}
	// missing file -> defaults
	l2, err := LoadWhitelist(filepath.Join(dir, "missing.txt"))
	if err != nil || !l2.Match("github.com") {
		t.Fatalf("default whitelist: %v", err)
	}
}

// TestStorageDriverAliases 验证存储驱动别名：minio -> s3（强制 path_style）、
// fs -> localfs、openlist 注册，未知驱动给出包含可选项的错误信息。
func TestStorageDriverAliases(t *testing.T) {
	dir := t.TempDir()

	newWithDriver := func(driver string) (*App, error) {
		cfg := Default(dir)
		cfg.Storage.Driver = driver
		switch driver {
		case "minio", "s3":
			cfg.Storage.S3 = S3Config{
				Endpoint: "http://minio.test:9000", Region: "us-east-1",
				Bucket: "b", AccessKeyID: "ak", SecretAccessKey: "sk",
			}
		case "openlist":
			cfg.Storage.OpenList = OpenListConfig{BaseURL: "http://openlist.test:5244", Token: "tok"}
		}
		return New(cfg)
	}

	a, err := newWithDriver("minio")
	if err != nil {
		t.Fatalf("minio alias: %v", err)
	}
	if a.Storage.Name() != "s3" {
		t.Fatalf("minio should map to the s3 driver, got %q", a.Storage.Name())
	}

	a2, err := newWithDriver("fs")
	if err != nil {
		t.Fatalf("fs alias: %v", err)
	}
	if a2.Storage.Name() != "localfs" {
		t.Fatalf("fs should map to the localfs driver, got %q", a2.Storage.Name())
	}

	a3, err := newWithDriver("openlist")
	if err != nil {
		t.Fatalf("openlist driver: %v", err)
	}
	if a3.Storage.Name() != "openlist" {
		t.Fatalf("openlist driver name = %q", a3.Storage.Name())
	}
	if a3.Local != nil {
		t.Fatal("openlist driver must not mount the localfs /files/ handler")
	}

	_, err = newWithDriver("webdav")
	if err == nil || !strings.Contains(err.Error(), "localfs | s3 | minio | openlist") {
		t.Fatalf("unknown driver error should list options, got: %v", err)
	}
}

// TestLoadAnnotatedExampleYAML 保证 deploy/server.example.yaml（带注释模板）
// 始终能被正确解析——它是用户手改配置的第一入口。
func TestLoadAnnotatedExampleYAML(t *testing.T) {
	path := filepath.Join("..", "..", "..", "deploy", "server.example.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("example not found: %v", err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("annotated example must parse: %v", err)
	}
	if cfg.Listen != "127.0.0.1:8080" {
		t.Errorf("listen = %q", cfg.Listen)
	}
	if cfg.Tunnel.Listen != "127.0.0.1:8081" || !cfg.Tunnel.Enabled {
		t.Errorf("tunnel = %+v", cfg.Tunnel)
	}
	if cfg.Storage.Driver != "localfs" || cfg.Storage.Secret == "" {
		t.Errorf("storage = %+v", cfg.Storage)
	}
	if cfg.Executor.Driver != "builtin" || cfg.Executor.AllowLoopback {
		t.Errorf("executor = %+v", cfg.Executor)
	}
	if !cfg.Auth.AllowRegistration {
		t.Errorf("auth = %+v", cfg.Auth)
	}
	if cfg.PresignTTLDuration() != 15*time.Minute {
		t.Errorf("presign ttl = %v", cfg.PresignTTLDuration())
	}
}

func writeWhitelist(path, content string) error {
	return osWriteFile(path, []byte(content))
}

var _ = fmt.Sprintf
