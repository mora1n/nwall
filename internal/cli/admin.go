package cli

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/mora1n/nwall/internal/protect"
	"github.com/mora1n/nwall/internal/store"
	appversion "github.com/mora1n/nwall/internal/version"
)

const (
	defaultPrefix     = "/usr/local"
	defaultStateDir   = "/var/lib/nwall"
	defaultSystemdDir = "/etc/systemd/system"
	defaultRepo       = "mora1n/nwall"
	checksumsName     = "SHA256SUMS"
)

var managedUnits = []string{
	"nwall.service",
}

var legacyUnits = []string{
	"nwall-dpi.service",
	"nwall-lease.service",
	"nwall-lease-trigger.service",
	"nwall-downmask.service",
	"nwall-downmask-reconcile.service",
	"nwall-downmask-reconcile.timer",
}

var restartableUnits = []string{
	"nwall.service",
}

func runUninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	keepConfig := fs.Bool("keep-config", false, "保留 nwall.db")
	purgeConfig := fs.Bool("purge-config", false, "删除 nwall.db")
	dryRun := fs.Bool("dry-run", false, "只打印动作")
	prefix := fs.String("prefix", defaultPrefix, "安装前缀")
	stateDir := fs.String("state-dir", defaultStateDir, "状态目录")
	systemdDir := fs.String("systemd-dir", defaultSystemdDir, "systemd unit 目录")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keepConfig && *purgeConfig {
		return fmt.Errorf("--keep-config 和 --purge-config 不能同时使用")
	}
	mode := "ask"
	if *keepConfig {
		mode = "keep"
	}
	if *purgeConfig {
		mode = "purge"
	}
	return uninstall(adminOptions{Prefix: *prefix, StateDir: *stateDir, SystemdDir: *systemdDir, DryRun: *dryRun, ConfigMode: mode})
}

func runUpdate(args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	version := fs.String("version", "latest", "latest 或 vX.Y.Z")
	repo := fs.String("repo", defaultRepo, "GitHub 仓库 owner/name")
	dryRun := fs.Bool("dry-run", false, "只打印动作")
	prefix := fs.String("prefix", defaultPrefix, "安装前缀")
	systemdDir := fs.String("systemd-dir", defaultSystemdDir, "systemd unit 目录")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return update(adminOptions{Prefix: *prefix, SystemdDir: *systemdDir, DryRun: *dryRun, Version: *version, Repo: *repo})
}

type adminOptions struct {
	Prefix     string
	StateDir   string
	SystemdDir string
	DryRun     bool
	ConfigMode string
	Version    string
	Repo       string
}

func uninstall(opts adminOptions) error {
	if opts.ConfigMode == "" {
		opts.ConfigMode = "ask"
	}
	disableArgs := append([]string{"disable", "--now"}, managedUnits...)
	if err := systemctl(opts.DryRun, disableArgs...); err != nil {
		fmt.Fprintf(os.Stderr, "停止服务失败（继续卸载）: %v\n", err)
	}
	if opts.DryRun {
		fmt.Println("DRY-RUN: nwall protect disable")
	} else if err := protect.Disable(); err != nil {
		return fmt.Errorf("清理 nftables 规则失败: %w", err)
	}
	binPath := filepath.Join(opts.Prefix, "bin", "nwall")
	if err := remove(opts.DryRun, binPath); err != nil {
		return err
	}
	for _, unit := range managedUnits {
		if err := remove(opts.DryRun, filepath.Join(opts.SystemdDir, unit)); err != nil {
			return err
		}
	}
	dbPath := filepath.Join(opts.StateDir, filepath.Base(store.DefaultPath))
	mode := opts.ConfigMode
	if mode == "ask" && !opts.DryRun && fileExists(dbPath) {
		fmt.Printf("删除 nwall DB %s? [y/N] ", dbPath)
		var answer string
		_, _ = fmt.Scanln(&answer)
		switch strings.ToLower(strings.TrimSpace(answer)) {
		case "y", "yes":
			mode = "purge"
		default:
			mode = "keep"
		}
	}
	if mode == "purge" {
		if opts.DryRun {
			fmt.Printf("DRY-RUN: rm -rf %s\n", opts.StateDir)
		} else {
			if err := os.RemoveAll(opts.StateDir); err != nil {
				return err
			}
		}
	} else {
		fmt.Printf("保留配置 DB: %s\n", dbPath)
		fmt.Printf("保留状态目录: %s\n", opts.StateDir)
		fmt.Println("重新安装时会复用该目录，nwall 会从同一路径加载 DB 和下行伪装 seed。")
	}
	if err := systemctl(opts.DryRun, "daemon-reload"); err != nil {
		return err
	}
	fmt.Println("nwall uninstall complete.")
	return nil
}

func update(opts adminOptions) error {
	if opts.Repo == "" {
		opts.Repo = defaultRepo
	}
	if opts.Version == "" {
		opts.Version = "latest"
	}
	version := opts.Version
	if opts.DryRun {
		dryRunUpdate(opts, version)
		return nil
	}
	var err error
	if version == "latest" {
		version, err = latestVersion(opts.Repo)
		if err != nil {
			return err
		}
	}
	if shouldSkipUpdate(appversion.Version, version) {
		fmt.Printf("nwall already at %s\n", version)
		return nil
	}
	tmpDir, err := os.MkdirTemp("", "nwall-update-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)
	srcDir, err := downloadRelease(opts.Repo, version, tmpDir)
	if err != nil {
		return err
	}
	backupDir, err := backupInstall(opts, tmpDir)
	if err != nil {
		return err
	}
	originalServices := activeOrEnabledUnits()
	restartServices := targetRestartUnits(originalServices)
	if err := installReleasePayload(srcDir, opts); err != nil {
		_ = restoreInstall(opts, backupDir, originalServices)
		return err
	}
	if err := removeLegacyUnits(opts); err != nil {
		_ = restoreInstall(opts, backupDir, originalServices)
		return err
	}
	if err := systemctl(false, "daemon-reload"); err != nil {
		_ = restoreInstall(opts, backupDir, originalServices)
		return err
	}
	if err := restartUnits(restartServices); err != nil {
		_ = restoreInstall(opts, backupDir, originalServices)
		return err
	}
	if err := healthCheck(opts, restartServices); err != nil {
		_ = restoreInstall(opts, backupDir, originalServices)
		return err
	}
	fmt.Printf("nwall updated to %s\n", version)
	return nil
}

func shouldSkipUpdate(current, target string) bool {
	current = normalizeReleaseVersion(current)
	target = normalizeReleaseVersion(target)
	return current != "" && current != "dev" && current == target
}

func normalizeReleaseVersion(value string) string {
	return strings.TrimPrefix(strings.TrimSpace(value), "v")
}

func dryRunUpdate(opts adminOptions, version string) {
	asset := fmt.Sprintf("nwall-linux-amd64-%s.tar.gz", version)
	base := fmt.Sprintf("https://github.com/%s/releases/download/%s", opts.Repo, version)
	fmt.Printf("DRY-RUN: resolve release %s from %s\n", version, opts.Repo)
	fmt.Printf("DRY-RUN: download %s\n", base+"/"+asset)
	fmt.Printf("DRY-RUN: download %s\n", base+"/"+checksumsName)
	fmt.Printf("DRY-RUN: verify %s with %s\n", asset, checksumsName)
	fmt.Printf("DRY-RUN: backup %s and systemd units to /tmp/nwall-update-*/backup-*\n", filepath.Join(opts.Prefix, "bin", "nwall"))
	fmt.Printf("DRY-RUN: atomically replace %s\n", filepath.Join(opts.Prefix, "bin", "nwall"))
	fmt.Printf("DRY-RUN: atomically replace systemd units in %s\n", opts.SystemdDir)
	fmt.Println("DRY-RUN: systemctl daemon-reload")
	fmt.Println("DRY-RUN: restart active/enabled nwall units")
	fmt.Println("DRY-RUN: health-check nwall version, protect status, and active services")
	fmt.Println("DRY-RUN: rollback from backup if any step fails")
}

func latestVersion(repo string) (string, error) {
	resp, err := http.Head("https://github.com/" + repo + "/releases/latest")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.Request == nil || resp.Request.URL == nil {
		return "", fmt.Errorf("无法解析 latest release")
	}
	version := pathBase(resp.Request.URL.Path)
	if version == "" || version == "latest" {
		return "", fmt.Errorf("无法解析 latest release: %s", resp.Request.URL.String())
	}
	return version, nil
}

func downloadRelease(repo, version, tmpDir string) (string, error) {
	asset := fmt.Sprintf("nwall-linux-amd64-%s.tar.gz", version)
	base := fmt.Sprintf("https://github.com/%s/releases/download/%s", repo, version)
	archive := filepath.Join(tmpDir, asset)
	sumFile := filepath.Join(tmpDir, checksumsName)
	if err := downloadFile(archive, base+"/"+asset); err != nil {
		return "", err
	}
	if err := downloadFile(sumFile, base+"/"+checksumsName); err != nil {
		return "", err
	}
	if err := verifySHA256(archive, sumFile); err != nil {
		return "", err
	}
	if err := extractTarGz(archive, tmpDir); err != nil {
		return "", err
	}
	srcDir := filepath.Join(tmpDir, fmt.Sprintf("nwall-linux-amd64-%s", version))
	if err := validateReleasePayload(srcDir); err != nil {
		return "", err
	}
	return srcDir, nil
}

func downloadFile(dst, url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("下载失败 %s: HTTP %d", url, resp.StatusCode)
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}

func verifySHA256(path, sumFile string) error {
	data, err := os.ReadFile(sumFile)
	if err != nil {
		return err
	}
	content := strings.TrimSpace(string(data))
	if content == "" {
		return fmt.Errorf("sha256 文件为空: %s", sumFile)
	}
	want, err := checksumForAsset(content, filepath.Base(path))
	if err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		return fmt.Errorf("sha256 mismatch: want %s got %s", want, got)
	}
	return nil
}

func checksumForAsset(content, asset string) (string, error) {
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		if name == asset {
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", fmt.Errorf("sha256 entry not found for %s", asset)
}

func extractTarGz(path, dst string) error {
	f, err := os.Open(path)
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
	cleanDst, err := filepath.Abs(dst)
	if err != nil {
		return err
	}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		target := filepath.Join(cleanDst, h.Name)
		if !strings.HasPrefix(target, cleanDst+string(os.PathSeparator)) {
			return fmt.Errorf("tar entry escapes destination: %s", h.Name)
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(h.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			if err := out.Close(); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported tar entry: %s", h.Name)
		}
	}
}

func backupInstall(opts adminOptions, tmpDir string) (string, error) {
	backupDir := filepath.Join(tmpDir, "backup-"+time.Now().Format("20060102150405"))
	if err := os.MkdirAll(filepath.Join(backupDir, "systemd"), 0o755); err != nil {
		return "", err
	}
	binPath := filepath.Join(opts.Prefix, "bin", "nwall")
	if !fileExists(binPath) {
		return "", fmt.Errorf("当前 nwall 二进制不存在: %s", binPath)
	}
	if err := copyFile(binPath, filepath.Join(backupDir, "nwall"), 0o755); err != nil {
		return "", err
	}
	for _, unit := range allKnownUnits() {
		if err := copyIfExists(filepath.Join(opts.SystemdDir, unit), filepath.Join(backupDir, "systemd", unit)); err != nil {
			return "", err
		}
	}
	return backupDir, nil
}

func installReleasePayload(srcDir string, opts adminOptions) error {
	if err := validateReleasePayload(srcDir); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(opts.Prefix, "bin"), 0o755); err != nil {
		return err
	}
	if err := copyFile(filepath.Join(srcDir, "nwall"), filepath.Join(opts.Prefix, "bin", "nwall"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(opts.SystemdDir, 0o755); err != nil {
		return err
	}
	for _, unit := range managedUnits {
		src := filepath.Join(srcDir, "systemd", unit)
		if err := copyFile(src, filepath.Join(opts.SystemdDir, unit), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func removeLegacyUnits(opts adminOptions) error {
	for _, unit := range legacyUnits {
		if err := remove(opts.DryRun, filepath.Join(opts.SystemdDir, unit)); err != nil {
			return err
		}
	}
	return nil
}

func validateReleasePayload(srcDir string) error {
	bin := filepath.Join(srcDir, "nwall")
	info, err := os.Stat(bin)
	if err != nil {
		return fmt.Errorf("release payload missing nwall: %w", err)
	}
	if info.IsDir() || info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("release payload nwall is not executable: %s", bin)
	}
	for _, unit := range managedUnits {
		path := filepath.Join(srcDir, "systemd", unit)
		if info, err := os.Stat(path); err != nil {
			return fmt.Errorf("release payload missing %s: %w", unit, err)
		} else if info.IsDir() {
			return fmt.Errorf("release payload unit is a directory: %s", path)
		}
	}
	return nil
}

func restoreInstall(opts adminOptions, backupDir string, services []string) error {
	if fileExists(filepath.Join(backupDir, "nwall")) {
		if err := copyFile(filepath.Join(backupDir, "nwall"), filepath.Join(opts.Prefix, "bin", "nwall"), 0o755); err != nil {
			return err
		}
	}
	for _, unit := range allKnownUnits() {
		src := filepath.Join(backupDir, "systemd", unit)
		dst := filepath.Join(opts.SystemdDir, unit)
		if fileExists(src) {
			if err := copyFile(src, dst, 0o644); err != nil {
				return err
			}
			continue
		}
		if err := remove(false, dst); err != nil {
			return err
		}
	}
	_ = systemctl(false, "daemon-reload")
	_ = restartUnits(services)
	return nil
}

func activeOrEnabledUnits() []string {
	out := []string{}
	for _, unit := range allKnownUnits() {
		if systemctlQuiet("is-enabled", unit) || systemctlQuiet("is-active", unit) {
			out = append(out, unit)
		}
	}
	return out
}

func targetRestartUnits(original []string) []string {
	if len(original) == 0 {
		return nil
	}
	return append([]string{}, restartableUnits...)
}

func allKnownUnits() []string {
	out := append([]string{}, managedUnits...)
	out = append(out, legacyUnits...)
	return out
}

func restartUnits(units []string) error {
	for _, unit := range units {
		if err := systemctl(false, "restart", unit); err != nil {
			return err
		}
	}
	return nil
}

func healthCheck(opts adminOptions, services []string) error {
	bin := filepath.Join(opts.Prefix, "bin", "nwall")
	if err := exec.Command(bin, "version").Run(); err != nil {
		return fmt.Errorf("version health-check failed: %w", err)
	}
	if err := exec.Command(bin, "protect", "status").Run(); err != nil {
		return fmt.Errorf("protect status health-check failed: %w", err)
	}
	for _, unit := range services {
		if !systemctlQuiet("is-active", unit) {
			return fmt.Errorf("unit health-check failed: %s is not active", unit)
		}
		if unit == "nwall.service" {
			if err := exec.Command(bin, "status").Run(); err != nil {
				return fmt.Errorf("daemon health-check failed: %w", err)
			}
		}
	}
	return nil
}

func systemctl(dryRun bool, args ...string) error {
	if dryRun {
		fmt.Printf("DRY-RUN: systemctl %s\n", strings.Join(args, " "))
		return nil
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil
	}
	cmd := exec.Command("systemctl", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func systemctlQuiet(args ...string) bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	cmd := exec.Command("systemctl", args...)
	return cmd.Run() == nil
}

func remove(dryRun bool, path string) error {
	if dryRun {
		fmt.Printf("DRY-RUN: rm -f %s\n", path)
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func copyIfExists(src, dst string) error {
	if !fileExists(src) {
		return nil
	}
	return copyFile(src, dst, 0)
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	if mode == 0 {
		mode = info.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func pathBase(path string) string {
	path = strings.TrimRight(path, "/")
	idx := strings.LastIndex(path, "/")
	if idx < 0 {
		return path
	}
	return path[idx+1:]
}
