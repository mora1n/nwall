package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mora1n/nwall/internal/daemon"
)

func runDaemon(args []string) error {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	socketPath := fs.String("socket", daemon.DefaultSocketPath, "Unix socket 路径")
	db := fs.String("db", dbPath(), "SQLite DB 路径")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return daemon.Run(ctx, daemon.Config{SocketPath: *socketPath, DBPath: *db})
}

func runDaemonStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	socketPath := fs.String("socket", daemon.DefaultSocketPath, "Unix socket 路径")
	if err := fs.Parse(args); err != nil {
		return err
	}
	data, err := daemonRequest(http.MethodGet, *socketPath, "/v1/status")
	if err != nil {
		return err
	}
	var status daemon.Status
	if err := json.Unmarshal(data, &status); err != nil {
		return err
	}
	fmt.Printf("daemon_ok: %v\n", status.OK)
	fmt.Printf("started_at: %s\n", status.StartedAt)
	fmt.Printf("reloaded_at: %s\n", status.ReloadedAt)
	for _, name := range []string{"protect", "dpi", "lease_agent", "lease_trigger", "downmask_server", "downmask_runner"} {
		c, ok := status.Components[name]
		if !ok {
			continue
		}
		line := fmt.Sprintf("%s: %s", name, c.State)
		if c.Message != "" {
			line += " (" + c.Message + ")"
		}
		if c.Error != "" {
			line += " error=" + c.Error
		}
		fmt.Println(line)
	}
	return nil
}

func runDaemonReload(args []string) error {
	fs := flag.NewFlagSet("reload", flag.ContinueOnError)
	socketPath := fs.String("socket", daemon.DefaultSocketPath, "Unix socket 路径")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := daemonRequest(http.MethodPost, *socketPath, "/v1/reload"); err != nil {
		return err
	}
	fmt.Println("daemon reloaded")
	return nil
}

func daemonRequest(method, socketPath, path string) ([]byte, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}
	req, err := http.NewRequest(method, "http://nwall"+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("连接 nwall daemon 失败: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if len(data) == 0 {
			return nil, fmt.Errorf("daemon HTTP %d", resp.StatusCode)
		}
		return nil, errors.New(string(data))
	}
	return data, nil
}
