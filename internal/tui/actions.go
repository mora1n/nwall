package tui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/mora1n/nwall/internal/conf"
	"github.com/mora1n/nwall/internal/daemon"
	"github.com/mora1n/nwall/internal/protect"
)

type defaultActions struct{}

func (defaultActions) Apply(cfg conf.Config, confirm bool, timeout int) error {
	if !cfg.Protect.Enabled {
		return errors.New("protect.enabled=false；先在 TUI 开启防护")
	}
	return protect.Apply(cfg, confirm, timeout)
}

func (defaultActions) Disable() error {
	return protect.Disable()
}

func (defaultActions) Reload() error {
	_, err := daemonRequest(http.MethodPost, "/v1/reload")
	return err
}

func (defaultActions) Status() (daemon.Status, error) {
	data, err := daemonRequest(http.MethodGet, "/v1/status")
	if err != nil {
		return daemon.Status{}, err
	}
	var status daemon.Status
	if err := json.Unmarshal(data, &status); err != nil {
		return daemon.Status{}, err
	}
	return status, nil
}

func daemonRequest(method, path string) ([]byte, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", daemon.DefaultSocketPath)
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
