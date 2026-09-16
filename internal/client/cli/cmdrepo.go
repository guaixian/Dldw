package cli

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"dldw/internal/client/config"
	"dldw/internal/client/downloader"
)

// cmdRepo 实现 `dldw repo <git-url> [dir]`：把 git 仓库快照转换为
// codeload tarball 走缓存下载并解包（Git 对象层缓存的务实路径——
// packfile 不可缓存，但同一 commit 的 tarball 内容恒定）。
//
//	dldw repo https://github.com/org/repo              # 默认分支 -> ./repo
//	dldw repo https://github.com/org/repo mydir        # 指定目录
//	dldw repo https://github.com/org/repo/tree/dev d2  # 指定分支
//
// 语义：当前快照、无 git 历史（需要完整历史请用 dldw git clone 走隧道）。
func cmdRepo(cfg config.Config, g globals, args []string) int {
	first, rest := newFlagSet("repo").Parse(args)
	if first == "" {
		fmt.Fprintln(os.Stderr, "usage: dldw repo <github-git-url> [dir]")
		fmt.Fprintln(os.Stderr, "  例: dldw repo https://github.com/julienschmidt/httprouter")
		return 2
	}
	rawURL := first
	outDir := ""
	if len(rest) > 0 {
		outDir = rest[0]
	}

	tarURL, repoName, err := repoTarballURL(rawURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dldw: %v\n", err)
		return 2
	}
	if outDir == "" {
		outDir = repoName
	}
	if _, err := os.Stat(outDir); err == nil {
		fmt.Fprintf(os.Stderr, "dldw: E_OUTPUT_EXISTS: %s already exists\n", outDir)
		return 1
	}

	server := config.EffectiveServer(g.server, cfg)
	token := resolveToken(cfg, g)
	var api *downloader.Client
	if server != "" && token != "" {
		api, err = downloader.NewAPIClient(server, token, clientIDOf(cfg), cfg.TLSSkipVerify)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dldw: %v\n", err)
			return 2
		}
	} else {
		fmt.Fprintln(os.Stderr, "dldw: no server/token, direct mode (no cache)")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	tmp := outDir + ".dldw-tmp.tgz"
	opts := downloader.Options{
		Concurrency: cfg.Concurrency(),
		ChunkSize:   cfg.ChunkSizeBytes(),
		Output:      tmp,
		Overwrite:   true,
		TaskTimeout: cfg.TaskTimeoutDur(),
		PollWait:    cfg.TaskPollWaitDur(),
	}
	res, err := downloader.Download(ctx, tarURL, opts, api)
	if err != nil {
		os.Remove(tmp)
		fmt.Fprintf(os.Stderr, "dldw: %v\n", err)
		return 1
	}
	defer os.Remove(tmp)

	if err := extractTarGz(res.Path, outDir); err != nil {
		fmt.Fprintf(os.Stderr, "dldw: extract: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "dldw: %s (%s, %s mode) -> %s\n", repoName, repoSizeFmt(res.Size), res.Mode, outDir)
	return 0
}

// repoTarballURL 把 github 仓库 URL 转换为 codeload tarball URL。
// 支持：github.com/<o>/<r>[.git]、github.com/<o>/<r>/tree/<branch>。
func repoTarballURL(raw string) (tarURL, repoName string, err error) {
	u, perr := url.Parse(raw)
	if perr != nil {
		return "", "", fmt.Errorf("bad url: %v", perr)
	}
	host := strings.ToLower(u.Host)
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if host != "github.com" || len(parts) < 2 {
		return "", "", fmt.Errorf("only github.com repos are supported (got %q); 需要完整历史请用 dldw git clone", raw)
	}
	owner, repo := parts[0], strings.TrimSuffix(parts[1], ".git")
	if owner == "" || repo == "" || strings.Contains(repo, ".git/") {
		return "", "", fmt.Errorf("bad repo url %q", raw)
	}
	ref := "HEAD"
	if len(parts) >= 4 && parts[2] == "tree" {
		ref = "refs/heads/" + parts[3]
	}
	return "https://codeload.github.com/" + owner + "/" + repo + "/tar.gz/" + ref, repo, nil
}

// extractTarGz 解包 tar.gz 并剥掉顶层目录（github tarball 的 <repo>-<sha>/ 前缀）。
func extractTarGz(tgz, dest string) error {
	f, err := os.Open(tgz)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	written := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := hdr.Name
		if i := strings.IndexByte(name, '/'); i >= 0 {
			name = name[i+1:] // strip <repo>-<sha>/
		} else {
			continue // 顶层目录条目本身
		}
		if name == "" {
			continue
		}
		target := filepath.Join(dest, filepath.FromSlash(name))
		if !strings.HasPrefix(target, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("tar entry escapes destination: %s", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode)&0o755)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			out.Close()
			written++
		case tar.TypeSymlink:
			// 出于安全不还原符号链接；保留为说明文件
			os.WriteFile(target+".dldw-symlink", []byte(hdr.Linkname), 0o644)
		}
	}
	if written == 0 {
		return fmt.Errorf("empty archive")
	}
	return nil
}

func repoSizeFmt(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.2f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.2f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
