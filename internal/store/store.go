// Package store owns nwall's SQLite-backed configuration and runtime state.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/mora1n/nwall/internal/conf"
	"github.com/mora1n/nwall/internal/geo"
)

const (
	// DefaultPath is the default persistent SQLite database path.
	DefaultPath = "/var/lib/nwall/nwall.db"
	// DefaultDownmaskSeedPath is the default external downmask seed file.
	DefaultDownmaskSeedPath = "/var/lib/nwall/downmask/seed.bin"

	SeedChunkSize     = 1024 * 1024
	DefaultSeedSize   = 1024 * 1024 * 1024
	bootstrapSeedSize = 8 * 1024 * 1024
)

// DB wraps a SQLite handle.
type DB struct {
	sql *sql.DB
}

// Open opens or initializes the nwall database.
func Open(path string) (*DB, error) {
	if strings.TrimSpace(path) == "" {
		path = DefaultPath
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("创建 DB 目录失败: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	out := &DB{sql: db}
	if err := out.init(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return out, nil
}

// Close closes the underlying database.
func (db *DB) Close() error {
	return db.sql.Close()
}

// SQL exposes the underlying handle for tests and small administrative queries.
func (db *DB) SQL() *sql.DB {
	return db.sql
}

func (db *DB) init(ctx context.Context) error {
	stmts := []string{
		`PRAGMA foreign_keys = ON`,
		`PRAGMA busy_timeout = 5000`,
		`CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS protect_config(
			id INTEGER PRIMARY KEY CHECK (id = 1),
			enabled INTEGER NOT NULL,
			rollback_timeout_sec INTEGER NOT NULL,
			guard_all INTEGER NOT NULL,
			block_http INTEGER NOT NULL,
			block_tls INTEGER NOT NULL,
			block_socks INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS protect_open_ports(port INTEGER PRIMARY KEY)`,
		`CREATE TABLE IF NOT EXISTS protect_guarded_ports(port INTEGER PRIMARY KEY)`,
		`CREATE TABLE IF NOT EXISTS protect_protocol_skip_ports(port INTEGER PRIMARY KEY)`,
		`CREATE TABLE IF NOT EXISTS protect_port_ranges(
			kind TEXT NOT NULL,
			position INTEGER NOT NULL,
			start_port INTEGER NOT NULL,
			end_port INTEGER NOT NULL,
			PRIMARY KEY (kind, position)
		)`,
		`CREATE TABLE IF NOT EXISTS ingress_config(
			id INTEGER PRIMARY KEY CHECK (id = 1),
			enabled INTEGER NOT NULL,
			cn_mode TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS ingress_cn_provinces(name TEXT PRIMARY KEY)`,
		`CREATE TABLE IF NOT EXISTS ingress_city_codes(code TEXT PRIMARY KEY)`,
		`CREATE TABLE IF NOT EXISTS ingress_custom_cidrs(cidr TEXT PRIMARY KEY)`,
		`CREATE TABLE IF NOT EXISTS ingress_port_policies(
			listen_port INTEGER PRIMARY KEY,
			cn_mode TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS ingress_port_policy_provinces(
			listen_port INTEGER NOT NULL,
			name TEXT NOT NULL,
			PRIMARY KEY (listen_port, name)
		)`,
		`CREATE TABLE IF NOT EXISTS ingress_port_policy_city_codes(
			listen_port INTEGER NOT NULL,
			code TEXT NOT NULL,
			PRIMARY KEY (listen_port, code)
		)`,
		`CREATE TABLE IF NOT EXISTS egress_config(
			id INTEGER PRIMARY KEY CHECK (id = 1),
			enabled INTEGER NOT NULL,
			cn_mode TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS egress_cn_provinces(name TEXT PRIMARY KEY)`,
		`CREATE TABLE IF NOT EXISTS egress_custom_cidrs(cidr TEXT PRIMARY KEY)`,
		`CREATE TABLE IF NOT EXISTS lease_config(
			id INTEGER PRIMARY KEY CHECK (id = 1),
			listen_host TEXT NOT NULL,
			listen_port INTEGER NOT NULL,
			lease_key TEXT NOT NULL,
			idle_ttl TEXT NOT NULL,
			ts_window_sec INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS lease_trusted_relay_cidrs(cidr TEXT PRIMARY KEY)`,
		`CREATE TABLE IF NOT EXISTS lease_routes(
			label TEXT PRIMARY KEY,
			idle_ttl TEXT NOT NULL,
			ipv4_prefix_len INTEGER NOT NULL,
			ipv6_prefix_len INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS lease_route_ip_allow_cidrs(
			label TEXT NOT NULL,
			cidr TEXT NOT NULL,
			PRIMARY KEY (label, cidr)
		)`,
		`CREATE TABLE IF NOT EXISTS lease_trigger_config(
			id INTEGER PRIMARY KEY CHECK (id = 1),
			enabled INTEGER NOT NULL DEFAULT 1,
			listen_host TEXT NOT NULL,
			listen_port INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS lease_trigger_trusted_proxy_cidrs(cidr TEXT PRIMARY KEY)`,
		`CREATE TABLE IF NOT EXISTS lease_trigger_routes(
			token TEXT PRIMARY KEY,
			label TEXT NOT NULL,
			target TEXT NOT NULL,
			idle_ttl TEXT NOT NULL,
			ipv4_prefix_len INTEGER NOT NULL,
			ipv6_prefix_len INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS downmask_config(
			id INTEGER PRIMARY KEY CHECK (id = 1),
			tcp_addr TEXT NOT NULL,
			udp_addr TEXT NOT NULL,
			token TEXT NOT NULL,
			seed_path TEXT NOT NULL,
			max_rate INTEGER NOT NULL,
			udp_payload_bytes INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS downmask_seed_chunks(
			chunk_index INTEGER PRIMARY KEY,
			data BLOB NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS downmask_status(
			id INTEGER PRIMARY KEY CHECK (id = 1),
			started_at TEXT NOT NULL,
			tcp_listening INTEGER NOT NULL,
			udp_listening INTEGER NOT NULL,
			bind_ip TEXT NOT NULL,
			tcp_port INTEGER NOT NULL,
			udp_port INTEGER NOT NULL,
			active_sessions INTEGER NOT NULL,
			total_bytes_sent INTEGER NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS downmask_policy(
			id INTEGER PRIMARY KEY CHECK (id = 1),
			pull_mode TEXT NOT NULL,
			iface TEXT NOT NULL,
			min_ratio REAL NOT NULL,
			max_ratio REAL NOT NULL,
			time_window_start TEXT NOT NULL,
			time_window_end TEXT NOT NULL,
			max_jitter_seconds INTEGER NOT NULL,
			min_deficit_bytes INTEGER NOT NULL,
			max_bytes_per_run INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS downmask_ab_pull_config(
			id INTEGER PRIMARY KEY CHECK (id = 1),
			protocol TEXT NOT NULL,
			protocol_mode TEXT NOT NULL,
			tcp_enabled INTEGER NOT NULL,
			udp_enabled INTEGER NOT NULL,
			remote_port INTEGER NOT NULL,
			local_ip TEXT NOT NULL,
			token TEXT NOT NULL,
			speed_limit TEXT NOT NULL,
			timeout_seconds INTEGER NOT NULL,
			parallel_limit INTEGER NOT NULL,
			speed_jitter_percent INTEGER NOT NULL,
			bytes_jitter_percent INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS downmask_ab_pull_targets(
			host TEXT PRIMARY KEY,
			port INTEGER NOT NULL,
			token TEXT NOT NULL,
			local_ip TEXT NOT NULL,
			weight INTEGER NOT NULL,
			tcp_enabled INTEGER NOT NULL,
			udp_enabled INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS downmask_day_state(
			id INTEGER PRIMARY KEY CHECK (id = 1),
			date TEXT NOT NULL,
			iface TEXT NOT NULL,
			target_ratio REAL NOT NULL,
			rx_accum INTEGER NOT NULL,
			tx_accum INTEGER NOT NULL,
			last_rx_raw INTEGER NOT NULL,
			last_tx_raw INTEGER NOT NULL,
			next_eligible_at INTEGER NOT NULL,
			previous_date TEXT NOT NULL,
			previous_target_ratio REAL,
			generation_source TEXT NOT NULL,
			generated_at TEXT NOT NULL,
			last_action TEXT NOT NULL,
			last_actual_bytes INTEGER NOT NULL,
			last_planned_bytes INTEGER NOT NULL,
			last_error TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS downmask_ratio_history(
			date TEXT PRIMARY KEY,
			target_ratio REAL NOT NULL,
			previous_date TEXT NOT NULL,
			previous_target_ratio REAL,
			generation_source TEXT NOT NULL,
			generated_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS runtime_state(
			key TEXT PRIMARY KEY,
			text_value TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS lease_nonces(
			scope TEXT NOT NULL,
			nonce TEXT NOT NULL,
			expires_at INTEGER NOT NULL,
			PRIMARY KEY (scope, nonce)
		)`,
	}
	for _, stmt := range stmts {
		if _, err := db.sql.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	if _, err := db.sql.ExecContext(ctx, `INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', '1')`); err != nil {
		return err
	}
	if err := db.migrateLeaseTCPOnly(ctx); err != nil {
		return err
	}
	if err := db.migrateLeaseTriggerEnabled(ctx); err != nil {
		return err
	}
	if err := db.migrateDownmaskExternalSeed(ctx); err != nil {
		return err
	}
	return db.ensureDefaults(ctx)
}

func (db *DB) migrateLeaseTCPOnly(ctx context.Context) error {
	if err := db.ensureColumn(ctx, "lease_config", "lease_key", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	return db.ensureColumn(ctx, "lease_routes", "idle_ttl", "TEXT NOT NULL DEFAULT ''")
}

func (db *DB) migrateLeaseTriggerEnabled(ctx context.Context) error {
	return db.ensureColumn(ctx, "lease_trigger_config", "enabled", "INTEGER NOT NULL DEFAULT 1")
}

func (db *DB) migrateDownmaskExternalSeed(ctx context.Context) error {
	spec := "TEXT NOT NULL DEFAULT '" + DefaultDownmaskSeedPath + "'"
	return db.ensureColumn(ctx, "downmask_config", "seed_path", spec)
}

func (db *DB) ensureColumn(ctx context.Context, table, column, spec string) error {
	rows, err := db.sql.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = db.sql.ExecContext(ctx, "ALTER TABLE "+table+" ADD COLUMN "+column+" "+spec)
	return err
}

func (db *DB) ensureDefaults(ctx context.Context) error {
	cfg := conf.Default()
	needsDefaultSeed, err := db.needsDefaultSeed(ctx)
	if err != nil {
		return err
	}
	if _, err := db.sql.ExecContext(ctx, `INSERT OR IGNORE INTO protect_config(id, enabled, rollback_timeout_sec, guard_all, block_http, block_tls, block_socks) VALUES(1, ?, ?, ?, ?, ?, ?)`,
		boolInt(cfg.Protect.Enabled), cfg.Protect.RollbackTimeoutSec, boolInt(cfg.Protect.GuardAll), boolInt(cfg.Protect.BlockHTTP), boolInt(cfg.Protect.BlockTLS), boolInt(cfg.Protect.BlockSOCKS)); err != nil {
		return err
	}
	if _, err := db.sql.ExecContext(ctx, `INSERT OR IGNORE INTO ingress_config(id, enabled, cn_mode) VALUES(1, ?, ?)`, boolInt(cfg.Ingress.Enabled), cfg.Ingress.CNMode); err != nil {
		return err
	}
	if _, err := db.sql.ExecContext(ctx, `INSERT OR IGNORE INTO egress_config(id, enabled, cn_mode) VALUES(1, ?, ?)`, boolInt(cfg.Egress.Enabled), cfg.Egress.CNMode); err != nil {
		return err
	}
	if _, err := db.sql.ExecContext(ctx, `INSERT OR IGNORE INTO lease_config(id, listen_host, listen_port, lease_key, idle_ttl, ts_window_sec) VALUES(1, ?, ?, '', ?, ?)`,
		cfg.Lease.ListenHost, cfg.Lease.ListenPort, cfg.Lease.IdleTTL, cfg.Lease.TSWindowSec); err != nil {
		return err
	}
	if _, err := db.sql.ExecContext(ctx, `INSERT OR IGNORE INTO lease_trigger_config(id, enabled, listen_host, listen_port) VALUES(1, ?, ?, ?)`,
		boolInt(cfg.LeaseTrigger.Enabled), cfg.LeaseTrigger.ListenHost, cfg.LeaseTrigger.ListenPort); err != nil {
		return err
	}
	if _, err := db.sql.ExecContext(ctx, `INSERT OR IGNORE INTO downmask_config(id, tcp_addr, udp_addr, token, seed_path, max_rate, udp_payload_bytes) VALUES(1, '', '', '', ?, 0, 1200)`, DefaultDownmaskSeedPath); err != nil {
		return err
	}
	if _, err := db.sql.ExecContext(ctx, `INSERT OR IGNORE INTO downmask_policy(id, pull_mode, iface, min_ratio, max_ratio, time_window_start, time_window_end, max_jitter_seconds, min_deficit_bytes, max_bytes_per_run)
		VALUES(1, 'off', '', 1.5, 2.0, '', '', 60, 20971520, 524288000)`); err != nil {
		return err
	}
	if _, err := db.sql.ExecContext(ctx, `INSERT OR IGNORE INTO downmask_ab_pull_config(id, protocol, protocol_mode, tcp_enabled, udp_enabled, remote_port, local_ip, token, speed_limit, timeout_seconds, parallel_limit, speed_jitter_percent, bytes_jitter_percent)
		VALUES(1, 'tcp', 'single', 1, 0, 0, '', '', '4M', 1200, 2, 0, 0)`); err != nil {
		return err
	}
	if needsDefaultSeed {
		if empty, err := db.tableEmpty(ctx, "protect_open_ports"); err != nil {
			return err
		} else if empty {
			for _, port := range cfg.Protect.OpenPorts {
				if _, err := db.sql.ExecContext(ctx, `INSERT OR IGNORE INTO protect_open_ports(port) VALUES(?)`, port); err != nil {
					return err
				}
			}
		}
		if empty, err := db.tableEmpty(ctx, "protect_protocol_skip_ports"); err != nil {
			return err
		} else if empty {
			for _, port := range cfg.Protect.ProtocolSkipPorts {
				if _, err := db.sql.ExecContext(ctx, `INSERT OR IGNORE INTO protect_protocol_skip_ports(port) VALUES(?)`, port); err != nil {
					return err
				}
			}
		}
		if _, err := db.sql.ExecContext(ctx, `INSERT OR REPLACE INTO meta(key, value) VALUES('defaults_initialized', '1')`); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) needsDefaultSeed(ctx context.Context) (bool, error) {
	var count int
	if err := db.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM meta WHERE key='defaults_initialized'`).Scan(&count); err != nil {
		return false, err
	}
	return count == 0, nil
}

func (db *DB) tableEmpty(ctx context.Context, table string) (bool, error) {
	var count int
	if err := db.sql.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil {
		return false, err
	}
	return count == 0, nil
}

// LoadConfig returns the assembled nwall configuration.
func (db *DB) LoadConfig() (conf.Config, error) {
	cfg := conf.Default()
	if err := db.sql.QueryRow(`SELECT enabled, rollback_timeout_sec, guard_all, block_http, block_tls, block_socks FROM protect_config WHERE id=1`).
		Scan((*boolScan)(&cfg.Protect.Enabled), &cfg.Protect.RollbackTimeoutSec, (*boolScan)(&cfg.Protect.GuardAll), (*boolScan)(&cfg.Protect.BlockHTTP), (*boolScan)(&cfg.Protect.BlockTLS), (*boolScan)(&cfg.Protect.BlockSOCKS)); err != nil {
		return conf.Config{}, err
	}
	var err error
	if cfg.Protect.OpenPorts, err = db.intList(`SELECT port FROM protect_open_ports ORDER BY port`); err != nil {
		return conf.Config{}, err
	}
	if cfg.Protect.OpenPortRanges, err = db.loadPortRanges("open"); err != nil {
		return conf.Config{}, err
	}
	if len(cfg.Protect.OpenPortRanges) == 0 && len(cfg.Protect.OpenPorts) > 0 {
		cfg.Protect.OpenPortRanges = compressPortsToRanges(cfg.Protect.OpenPorts)
	}
	if cfg.Protect.GuardedPorts, err = db.intList(`SELECT port FROM protect_guarded_ports ORDER BY port`); err != nil {
		return conf.Config{}, err
	}
	if cfg.Protect.ProtocolSkipPorts, err = db.intList(`SELECT port FROM protect_protocol_skip_ports ORDER BY port`); err != nil {
		return conf.Config{}, err
	}
	if err := db.sql.QueryRow(`SELECT enabled, cn_mode FROM ingress_config WHERE id=1`).
		Scan((*boolScan)(&cfg.Ingress.Enabled), &cfg.Ingress.CNMode); err != nil {
		return conf.Config{}, err
	}
	if cfg.Ingress.CNProvinces, err = db.stringList(`SELECT name FROM ingress_cn_provinces ORDER BY name`); err != nil {
		return conf.Config{}, err
	}
	if cfg.Ingress.CNCityCodes, err = db.stringList(`SELECT code FROM ingress_city_codes ORDER BY code`); err != nil {
		return conf.Config{}, err
	}
	if cfg.Ingress.CustomCIDRs, err = db.stringList(`SELECT cidr FROM ingress_custom_cidrs ORDER BY cidr`); err != nil {
		return conf.Config{}, err
	}
	if cfg.Ingress.PortPolicies, err = db.loadPortPolicies(); err != nil {
		return conf.Config{}, err
	}
	if err := db.sql.QueryRow(`SELECT enabled, cn_mode FROM egress_config WHERE id=1`).
		Scan((*boolScan)(&cfg.Egress.Enabled), &cfg.Egress.CNMode); err != nil {
		return conf.Config{}, err
	}
	if cfg.Egress.CNProvinces, err = db.stringList(`SELECT name FROM egress_cn_provinces ORDER BY name`); err != nil {
		return conf.Config{}, err
	}
	if cfg.Egress.CustomCIDRs, err = db.stringList(`SELECT cidr FROM egress_custom_cidrs ORDER BY cidr`); err != nil {
		return conf.Config{}, err
	}
	if err := db.sql.QueryRow(`SELECT listen_host, listen_port, lease_key, idle_ttl, ts_window_sec FROM lease_config WHERE id=1`).
		Scan(&cfg.Lease.ListenHost, &cfg.Lease.ListenPort, &cfg.Lease.LeaseKey, &cfg.Lease.IdleTTL, &cfg.Lease.TSWindowSec); err != nil {
		return conf.Config{}, err
	}
	if cfg.Lease.TrustedRelayCIDRs, err = db.stringList(`SELECT cidr FROM lease_trusted_relay_cidrs ORDER BY cidr`); err != nil {
		return conf.Config{}, err
	}
	if cfg.Lease.Routes, err = db.loadLeaseRoutes(); err != nil {
		return conf.Config{}, err
	}
	if err := db.sql.QueryRow(`SELECT enabled, listen_host, listen_port FROM lease_trigger_config WHERE id=1`).
		Scan((*boolScan)(&cfg.LeaseTrigger.Enabled), &cfg.LeaseTrigger.ListenHost, &cfg.LeaseTrigger.ListenPort); err != nil {
		return conf.Config{}, err
	}
	if cfg.LeaseTrigger.TrustedProxyCIDRs, err = db.stringList(`SELECT cidr FROM lease_trigger_trusted_proxy_cidrs ORDER BY cidr`); err != nil {
		return conf.Config{}, err
	}
	if cfg.LeaseTrigger.Routes, err = db.loadLeaseTriggerRoutes(); err != nil {
		return conf.Config{}, err
	}
	conf.ApplyFallbacks(&cfg)
	if err := conf.Validate(cfg); err != nil {
		return conf.Config{}, err
	}
	return cfg, nil
}

// SaveConfig stores a complete config by splitting it into module tables.
func (db *DB) SaveConfig(cfg conf.Config) error {
	conf.ApplyFallbacks(&cfg)
	var err error
	cfg.Protect, err = db.normalizeProtectForSave(cfg.Protect)
	if err != nil {
		return err
	}
	if err := conf.Validate(cfg); err != nil {
		return err
	}
	tx, err := db.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := saveProtectTx(tx, cfg.Protect); err != nil {
		return err
	}
	if err := saveIngressTx(tx, cfg.Ingress); err != nil {
		return err
	}
	if err := saveEgressTx(tx, cfg.Egress); err != nil {
		return err
	}
	if err := saveLeaseTx(tx, cfg.Lease); err != nil {
		return err
	}
	if err := saveLeaseTriggerTx(tx, cfg.LeaseTrigger); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) normalizeProtectForSave(cfg conf.Protect) (conf.Protect, error) {
	expandedRanges := expandPortRanges(cfg.OpenPortRanges)
	ports := uniqueInts(cfg.OpenPorts)
	if sameInts(expandedRanges, ports) {
		return cfg, nil
	}
	currentRanges, err := db.currentOpenPortRanges()
	if err != nil {
		return conf.Protect{}, err
	}
	if len(cfg.OpenPortRanges) == 0 || samePortRanges(cfg.OpenPortRanges, currentRanges) {
		cfg.OpenPortRanges = compressPortsToRanges(ports)
		cfg.OpenPorts = ports
		return cfg, nil
	}
	cfg.OpenPorts = expandedRanges
	return cfg, nil
}

func (db *DB) currentOpenPortRanges() ([]conf.PortRange, error) {
	ranges, err := db.loadPortRanges("open")
	if err != nil {
		return nil, err
	}
	if len(ranges) > 0 {
		return ranges, nil
	}
	ports, err := db.intList(`SELECT port FROM protect_open_ports ORDER BY port`)
	if err != nil {
		return nil, err
	}
	return compressPortsToRanges(ports), nil
}

func (db *DB) stringList(query string, args ...any) ([]string, error) {
	rows, err := db.sql.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, rows.Err()
}

func (db *DB) intList(query string, args ...any) ([]int, error) {
	rows, err := db.sql.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var value int
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, rows.Err()
}

func (db *DB) loadPortRanges(kind string) ([]conf.PortRange, error) {
	rows, err := db.sql.Query(`SELECT start_port, end_port FROM protect_port_ranges WHERE kind=? ORDER BY position`, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []conf.PortRange
	for rows.Next() {
		var r conf.PortRange
		if err := rows.Scan(&r.Start, &r.End); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (db *DB) loadPortPolicies() ([]conf.PortPolicy, error) {
	rows, err := db.sql.Query(`SELECT listen_port, cn_mode FROM ingress_port_policies ORDER BY listen_port`)
	if err != nil {
		return nil, err
	}
	var out []conf.PortPolicy
	for rows.Next() {
		var p conf.PortPolicy
		if err := rows.Scan(&p.ListenPort, &p.CNMode); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for i := range out {
		out[i].CNProvinces, err = db.stringList(`SELECT name FROM ingress_port_policy_provinces WHERE listen_port=? ORDER BY name`, out[i].ListenPort)
		if err != nil {
			return nil, err
		}
		out[i].CNCityCodes, err = db.stringList(`SELECT code FROM ingress_port_policy_city_codes WHERE listen_port=? ORDER BY code`, out[i].ListenPort)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (db *DB) loadLeaseRoutes() ([]conf.Route, error) {
	rows, err := db.sql.Query(`SELECT label, idle_ttl, ipv4_prefix_len, ipv6_prefix_len FROM lease_routes ORDER BY label`)
	if err != nil {
		return nil, err
	}
	var out []conf.Route
	for rows.Next() {
		var r conf.Route
		if err := rows.Scan(&r.Label, &r.IdleTTL, &r.IPv4PrefixLen, &r.IPv6PrefixLen); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for i := range out {
		out[i].IPAllowCIDRs, err = db.stringList(`SELECT cidr FROM lease_route_ip_allow_cidrs WHERE label=? ORDER BY cidr`, out[i].Label)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (db *DB) loadLeaseTriggerRoutes() ([]conf.TriggerRoute, error) {
	rows, err := db.sql.Query(`SELECT token, label, target, idle_ttl, ipv4_prefix_len, ipv6_prefix_len FROM lease_trigger_routes ORDER BY token`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []conf.TriggerRoute
	for rows.Next() {
		var r conf.TriggerRoute
		if err := rows.Scan(&r.Token, &r.Label, &r.Target, &r.IdleTTL, &r.IPv4PrefixLen, &r.IPv6PrefixLen); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func saveProtectTx(tx *sql.Tx, cfg conf.Protect) error {
	if _, err := tx.Exec(`UPDATE protect_config SET enabled=?, rollback_timeout_sec=?, guard_all=?, block_http=?, block_tls=?, block_socks=? WHERE id=1`,
		boolInt(cfg.Enabled), cfg.RollbackTimeoutSec, boolInt(cfg.GuardAll), boolInt(cfg.BlockHTTP), boolInt(cfg.BlockTLS), boolInt(cfg.BlockSOCKS)); err != nil {
		return err
	}
	if len(cfg.OpenPortRanges) == 0 && len(cfg.OpenPorts) > 0 {
		cfg.OpenPortRanges = compressPortsToRanges(cfg.OpenPorts)
	}
	cfg.OpenPorts = expandPortRanges(cfg.OpenPortRanges)
	if err := replacePortRanges(tx, "open", cfg.OpenPortRanges); err != nil {
		return err
	}
	if err := replaceInts(tx, "protect_open_ports", "port", cfg.OpenPorts); err != nil {
		return err
	}
	if err := replaceInts(tx, "protect_guarded_ports", "port", cfg.GuardedPorts); err != nil {
		return err
	}
	return replaceInts(tx, "protect_protocol_skip_ports", "port", cfg.ProtocolSkipPorts)
}

func saveIngressTx(tx *sql.Tx, cfg conf.Ingress) error {
	cfg = normalizeIngress(cfg)
	if _, err := tx.Exec(`UPDATE ingress_config SET enabled=?, cn_mode=? WHERE id=1`, boolInt(cfg.Enabled), cfg.CNMode); err != nil {
		return err
	}
	if err := replaceStrings(tx, "ingress_cn_provinces", "name", cfg.CNProvinces); err != nil {
		return err
	}
	if err := replaceStrings(tx, "ingress_city_codes", "code", cfg.CNCityCodes); err != nil {
		return err
	}
	if err := replaceStrings(tx, "ingress_custom_cidrs", "cidr", cfg.CustomCIDRs); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM ingress_port_policies`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM ingress_port_policy_provinces`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM ingress_port_policy_city_codes`); err != nil {
		return err
	}
	for _, p := range cfg.PortPolicies {
		if _, err := tx.Exec(`INSERT INTO ingress_port_policies(listen_port, cn_mode) VALUES(?, ?)`, p.ListenPort, p.CNMode); err != nil {
			return err
		}
		for _, name := range uniqueStrings(p.CNProvinces) {
			if _, err := tx.Exec(`INSERT INTO ingress_port_policy_provinces(listen_port, name) VALUES(?, ?)`, p.ListenPort, name); err != nil {
				return err
			}
		}
		for _, code := range uniqueStrings(p.CNCityCodes) {
			if _, err := tx.Exec(`INSERT INTO ingress_port_policy_city_codes(listen_port, code) VALUES(?, ?)`, p.ListenPort, code); err != nil {
				return err
			}
		}
	}
	return nil
}

func saveEgressTx(tx *sql.Tx, cfg conf.Egress) error {
	if _, err := tx.Exec(`UPDATE egress_config SET enabled=?, cn_mode=? WHERE id=1`, boolInt(cfg.Enabled), cfg.CNMode); err != nil {
		return err
	}
	if err := replaceStrings(tx, "egress_cn_provinces", "name", cfg.CNProvinces); err != nil {
		return err
	}
	return replaceStrings(tx, "egress_custom_cidrs", "cidr", cfg.CustomCIDRs)
}

func saveLeaseTx(tx *sql.Tx, cfg conf.Lease) error {
	if _, err := tx.Exec(`UPDATE lease_config SET listen_host=?, listen_port=?, lease_key=?, idle_ttl=?, ts_window_sec=? WHERE id=1`,
		cfg.ListenHost, cfg.ListenPort, cfg.LeaseKey, cfg.IdleTTL, cfg.TSWindowSec); err != nil {
		return err
	}
	if err := replaceStrings(tx, "lease_trusted_relay_cidrs", "cidr", cfg.TrustedRelayCIDRs); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM lease_routes`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM lease_route_ip_allow_cidrs`); err != nil {
		return err
	}
	hasMode, err := tableHasColumnTx(tx, "lease_routes", "mode")
	if err != nil {
		return err
	}
	for _, r := range cfg.Routes {
		if hasMode {
			if _, err := tx.Exec(`INSERT INTO lease_routes(label, mode, idle_ttl, ipv4_prefix_len, ipv6_prefix_len) VALUES(?, 'tcp', ?, ?, ?)`,
				r.Label, r.IdleTTL, r.IPv4PrefixLen, r.IPv6PrefixLen); err != nil {
				return err
			}
		} else {
			if _, err := tx.Exec(`INSERT INTO lease_routes(label, idle_ttl, ipv4_prefix_len, ipv6_prefix_len) VALUES(?, ?, ?, ?)`,
				r.Label, r.IdleTTL, r.IPv4PrefixLen, r.IPv6PrefixLen); err != nil {
				return err
			}
		}
		for _, cidr := range uniqueStrings(r.IPAllowCIDRs) {
			if _, err := tx.Exec(`INSERT INTO lease_route_ip_allow_cidrs(label, cidr) VALUES(?, ?)`, r.Label, cidr); err != nil {
				return err
			}
		}
	}
	return nil
}

func saveLeaseTriggerTx(tx *sql.Tx, cfg conf.LeaseTrigger) error {
	if _, err := tx.Exec(`UPDATE lease_trigger_config SET enabled=?, listen_host=?, listen_port=? WHERE id=1`,
		boolInt(cfg.Enabled), cfg.ListenHost, cfg.ListenPort); err != nil {
		return err
	}
	if err := replaceStrings(tx, "lease_trigger_trusted_proxy_cidrs", "cidr", cfg.TrustedProxyCIDRs); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM lease_trigger_routes`); err != nil {
		return err
	}
	for _, r := range cfg.Routes {
		if _, err := tx.Exec(`INSERT INTO lease_trigger_routes(token, label, target, idle_ttl, ipv4_prefix_len, ipv6_prefix_len) VALUES(?, ?, ?, ?, ?, ?)`,
			r.Token, r.Label, r.Target, r.IdleTTL, r.IPv4PrefixLen, r.IPv6PrefixLen); err != nil {
			return err
		}
	}
	return nil
}

func tableHasColumnTx(tx *sql.Tx, table, column string) (bool, error) {
	rows, err := tx.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

func replaceStrings(tx *sql.Tx, table, col string, values []string) error {
	if _, err := tx.Exec("DELETE FROM " + table); err != nil {
		return err
	}
	for _, value := range uniqueStrings(values) {
		if _, err := tx.Exec("INSERT INTO "+table+"("+col+") VALUES(?)", value); err != nil {
			return err
		}
	}
	return nil
}

func replaceInts(tx *sql.Tx, table, col string, values []int) error {
	if _, err := tx.Exec("DELETE FROM " + table); err != nil {
		return err
	}
	for _, value := range uniqueInts(values) {
		if _, err := tx.Exec("INSERT INTO "+table+"("+col+") VALUES(?)", value); err != nil {
			return err
		}
	}
	return nil
}

func replacePortRanges(tx *sql.Tx, kind string, ranges []conf.PortRange) error {
	if _, err := tx.Exec(`DELETE FROM protect_port_ranges WHERE kind=?`, kind); err != nil {
		return err
	}
	for i, r := range ranges {
		if _, err := tx.Exec(`INSERT INTO protect_port_ranges(kind, position, start_port, end_port) VALUES(?, ?, ?, ?)`, kind, i, r.Start, r.End); err != nil {
			return err
		}
	}
	return nil
}

func expandPortRanges(ranges []conf.PortRange) []int {
	seen := map[int]struct{}{}
	var out []int
	for _, r := range ranges {
		for port := r.Start; port <= r.End; port++ {
			if _, ok := seen[port]; ok {
				continue
			}
			seen[port] = struct{}{}
			out = append(out, port)
		}
	}
	sort.Ints(out)
	return out
}

func compressPortsToRanges(ports []int) []conf.PortRange {
	values := uniqueInts(ports)
	if len(values) == 0 {
		return nil
	}
	out := make([]conf.PortRange, 0, len(values))
	start := values[0]
	prev := values[0]
	for _, port := range values[1:] {
		if port == prev+1 {
			prev = port
			continue
		}
		out = append(out, conf.PortRange{Start: start, End: prev})
		start = port
		prev = port
	}
	return append(out, conf.PortRange{Start: start, End: prev})
}

func normalizeIngress(cfg conf.Ingress) conf.Ingress {
	cfg.CNProvinces = uniqueStrings(cfg.CNProvinces)
	cfg.CNCityCodes = uniqueStrings(cfg.CNCityCodes)
	cfg.CNCityCodes = dropCoveredCityCodes(cfg.CNProvinces, cfg.CNCityCodes)
	cfg.CustomCIDRs = uniqueStrings(cfg.CustomCIDRs)
	for i := range cfg.PortPolicies {
		cfg.PortPolicies[i].CNProvinces = uniqueStrings(cfg.PortPolicies[i].CNProvinces)
		cfg.PortPolicies[i].CNCityCodes = uniqueStrings(cfg.PortPolicies[i].CNCityCodes)
		cfg.PortPolicies[i].CNCityCodes = dropCoveredCityCodes(cfg.PortPolicies[i].CNProvinces, cfg.PortPolicies[i].CNCityCodes)
	}
	sort.Slice(cfg.PortPolicies, func(i, j int) bool {
		return cfg.PortPolicies[i].ListenPort < cfg.PortPolicies[j].ListenPort
	})
	return cfg
}

func dropCoveredCityCodes(provinces, codes []string) []string {
	if len(provinces) == 0 || len(codes) == 0 {
		return codes
	}
	selected := map[string]struct{}{}
	for _, province := range provinces {
		selected[province] = struct{}{}
	}
	db, err := geo.Default()
	if err != nil {
		return codes
	}
	out := make([]string, 0, len(codes))
	for _, code := range codes {
		province, ok := db.CityProvince(code)
		if ok {
			if _, covered := selected[province]; covered {
				continue
			}
		}
		out = append(out, code)
	}
	return out
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func uniqueInts(in []int) []int {
	seen := map[int]struct{}{}
	out := make([]int, 0, len(in))
	for _, item := range in {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	sort.Ints(out)
	return out
}

func sameInts(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func samePortRanges(left, right []conf.PortRange) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

// RuntimeValue returns a runtime text value by key.
func (db *DB) RuntimeValue(key string) (string, error) {
	var value string
	err := db.sql.QueryRow(`SELECT text_value FROM runtime_state WHERE key=?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", os.ErrNotExist
	}
	return value, err
}

// SetRuntimeValue stores a runtime text value.
func (db *DB) SetRuntimeValue(key, value string) error {
	_, err := db.sql.Exec(`INSERT INTO runtime_state(key, text_value, updated_at) VALUES(?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET text_value=excluded.text_value, updated_at=excluded.updated_at`,
		key, value, time.Now().UTC().Format(time.RFC3339))
	return err
}

// DeleteRuntimeValue deletes a runtime text value.
func (db *DB) DeleteRuntimeValue(key string) error {
	_, err := db.sql.Exec(`DELETE FROM runtime_state WHERE key=?`, key)
	return err
}

// RecordNonce records nonce when new; false means replay.
func (db *DB) RecordNonce(scope, nonce string, expires time.Time) (bool, error) {
	now := time.Now().Unix()
	if _, err := db.sql.Exec(`DELETE FROM lease_nonces WHERE expires_at < ?`, now); err != nil {
		return false, err
	}
	res, err := db.sql.Exec(`INSERT OR IGNORE INTO lease_nonces(scope, nonce, expires_at) VALUES(?, ?, ?)`, scope, nonce, expires.Unix())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// DownmaskConfig is the persisted downmask server configuration.
type DownmaskConfig struct {
	TCPAddr         string
	UDPAddr         string
	Token           string
	SeedPath        string
	MaxRate         uint64
	UDPPayloadBytes int
}

// LoadDownmaskConfig loads downmask server configuration.
func (db *DB) LoadDownmaskConfig() (DownmaskConfig, error) {
	var cfg DownmaskConfig
	var maxRate int64
	if err := db.sql.QueryRow(`SELECT tcp_addr, udp_addr, token, seed_path, max_rate, udp_payload_bytes FROM downmask_config WHERE id=1`).
		Scan(&cfg.TCPAddr, &cfg.UDPAddr, &cfg.Token, &cfg.SeedPath, &maxRate, &cfg.UDPPayloadBytes); err != nil {
		return DownmaskConfig{}, err
	}
	if strings.TrimSpace(cfg.SeedPath) == "" {
		cfg.SeedPath = DefaultDownmaskSeedPath
	}
	cfg.MaxRate = uint64(maxRate)
	return cfg, nil
}

// SaveDownmaskConfig stores downmask server configuration.
func (db *DB) SaveDownmaskConfig(cfg DownmaskConfig) error {
	if strings.TrimSpace(cfg.SeedPath) == "" {
		cfg.SeedPath = DefaultDownmaskSeedPath
	}
	_, err := db.sql.Exec(`UPDATE downmask_config SET tcp_addr=?, udp_addr=?, token=?, seed_path=?, max_rate=?, udp_payload_bytes=? WHERE id=1`,
		cfg.TCPAddr, cfg.UDPAddr, cfg.Token, cfg.SeedPath, int64(cfg.MaxRate), cfg.UDPPayloadBytes)
	return err
}

// GenerateDownmaskSeed replaces DB-backed seed chunks with cryptographic random data.
func (db *DB) GenerateDownmaskSeed(size int64) error {
	if size <= 0 {
		return fmt.Errorf("seed size must be > 0")
	}
	tx, err := db.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM downmask_seed_chunks`); err != nil {
		return err
	}
	buf := make([]byte, SeedChunkSize)
	var written int64
	index := 0
	for written < size {
		n := int64(len(buf))
		if remaining := size - written; remaining < n {
			n = remaining
		}
		if _, err := rand.Read(buf[:n]); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO downmask_seed_chunks(chunk_index, data) VALUES(?, ?)`, index, append([]byte(nil), buf[:n]...)); err != nil {
			return err
		}
		written += n
		index++
	}
	return tx.Commit()
}

// EnsureBootstrapSeed creates a modest seed when no DB seed exists.
func (db *DB) EnsureBootstrapSeed() error {
	var count int
	if err := db.sql.QueryRow(`SELECT COUNT(*) FROM downmask_seed_chunks`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	return db.GenerateDownmaskSeed(bootstrapSeedSize)
}

// SeedSize returns total seed bytes.
func (db *DB) SeedSize() (int64, error) {
	var total sql.NullInt64
	if err := db.sql.QueryRow(`SELECT COALESCE(SUM(LENGTH(data)), 0) FROM downmask_seed_chunks`).Scan(&total); err != nil {
		return 0, err
	}
	if !total.Valid {
		return 0, nil
	}
	return total.Int64, nil
}

// SeedReader is an io.ReaderAt over DB-backed seed chunks.
type SeedReader struct {
	db    *DB
	size  int64
	cache map[int][]byte
	order []int
}

// NewSeedReader returns a DB-backed seed reader.
func (db *DB) NewSeedReader() (*SeedReader, error) {
	size, err := db.SeedSize()
	if err != nil {
		return nil, err
	}
	if size <= 0 {
		return nil, fmt.Errorf("downmask seed 为空，请先运行 nwall downmask seed")
	}
	return &SeedReader{db: db, size: size, cache: map[int][]byte{}}, nil
}

// Size returns total seed bytes.
func (r *SeedReader) Size() int64 {
	return r.size
}

// ReadRandom fills p with random bytes from the persisted seed.
func (r *SeedReader) ReadRandom(p []byte) error {
	if len(p) == 0 {
		return nil
	}
	if int64(len(p)) > r.size {
		return r.ReadSequential(p)
	}
	limit := r.size - int64(len(p)) + 1
	off, err := cryptoRandInt64(limit)
	if err != nil {
		return err
	}
	_, err = r.ReadAt(p, off)
	return err
}

// ReadSequential fills p from random seed offsets until p is full.
func (r *SeedReader) ReadSequential(p []byte) error {
	pos := 0
	for pos < len(p) {
		off, err := cryptoRandInt64(r.size)
		if err != nil {
			return err
		}
		n, err := r.ReadAt(p[pos:], off)
		pos += n
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
	}
	return nil
}

// ReadAt reads from DB seed chunks.
func (r *SeedReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	if off >= r.size {
		return 0, io.EOF
	}
	total := 0
	for len(p) > 0 && off < r.size {
		chunkIndex := int(off / SeedChunkSize)
		chunkOff := int(off % SeedChunkSize)
		chunk, err := r.chunk(chunkIndex)
		if err != nil {
			return total, err
		}
		if chunkOff >= len(chunk) {
			return total, io.EOF
		}
		n := copy(p, chunk[chunkOff:])
		total += n
		p = p[n:]
		off += int64(n)
	}
	if len(p) > 0 {
		return total, io.EOF
	}
	return total, nil
}

func (r *SeedReader) chunk(index int) ([]byte, error) {
	if data, ok := r.cache[index]; ok {
		return data, nil
	}
	var data []byte
	if err := r.db.sql.QueryRow(`SELECT data FROM downmask_seed_chunks WHERE chunk_index=?`, index).Scan(&data); err != nil {
		return nil, err
	}
	r.cache[index] = data
	r.order = append(r.order, index)
	if len(r.order) > 8 {
		evict := r.order[0]
		r.order = r.order[1:]
		delete(r.cache, evict)
	}
	return data, nil
}

func cryptoRandInt64(limit int64) (int64, error) {
	if limit <= 0 {
		return 0, fmt.Errorf("无效随机上界: %d", limit)
	}
	if limit == 1 {
		return 0, nil
	}
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}
	return int64(binary.BigEndian.Uint64(buf[:]) % uint64(limit)), nil
}

// DownmaskStatus is the persisted status snapshot.
type DownmaskStatus struct {
	StartedAt      string
	TCPListening   bool
	UDPListening   bool
	BindIP         string
	TCPPort        int
	UDPPort        int
	ActiveSessions int
	TotalBytesSent uint64
	UpdatedAt      string
}

// SaveDownmaskStatus stores status.
func (db *DB) SaveDownmaskStatus(s DownmaskStatus) error {
	_, err := db.sql.Exec(`INSERT INTO downmask_status(id, started_at, tcp_listening, udp_listening, bind_ip, tcp_port, udp_port, active_sessions, total_bytes_sent, updated_at)
		VALUES(1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET started_at=excluded.started_at, tcp_listening=excluded.tcp_listening, udp_listening=excluded.udp_listening,
			bind_ip=excluded.bind_ip, tcp_port=excluded.tcp_port, udp_port=excluded.udp_port, active_sessions=excluded.active_sessions,
			total_bytes_sent=excluded.total_bytes_sent, updated_at=excluded.updated_at`,
		s.StartedAt, boolInt(s.TCPListening), boolInt(s.UDPListening), s.BindIP, s.TCPPort, s.UDPPort, s.ActiveSessions, int64(s.TotalBytesSent), s.UpdatedAt)
	return err
}

// LoadDownmaskStatus loads the most recent downmask server status snapshot.
func (db *DB) LoadDownmaskStatus() (DownmaskStatus, bool, error) {
	var s DownmaskStatus
	var tcp, udp boolScan
	err := db.sql.QueryRow(`SELECT started_at, tcp_listening, udp_listening, bind_ip, tcp_port, udp_port, active_sessions, total_bytes_sent, updated_at FROM downmask_status WHERE id=1`).
		Scan(&s.StartedAt, &tcp, &udp, &s.BindIP, &s.TCPPort, &s.UDPPort, &s.ActiveSessions, &s.TotalBytesSent, &s.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return DownmaskStatus{}, false, nil
	}
	if err != nil {
		return DownmaskStatus{}, false, err
	}
	s.TCPListening = bool(tcp)
	s.UDPListening = bool(udp)
	return s, true, nil
}

// DownmaskPolicy controls automatic downmask pull reconciliation.
type DownmaskPolicy struct {
	PullMode         string
	Iface            string
	MinRatio         float64
	MaxRatio         float64
	TimeWindowStart  string
	TimeWindowEnd    string
	MaxJitterSeconds int
	MinDeficitBytes  uint64
	MaxBytesPerRun   uint64
}

// LoadDownmaskPolicy loads automatic downmask policy.
func (db *DB) LoadDownmaskPolicy() (DownmaskPolicy, error) {
	var p DownmaskPolicy
	var minDeficit, maxRun int64
	err := db.sql.QueryRow(`SELECT pull_mode, iface, min_ratio, max_ratio, time_window_start, time_window_end, max_jitter_seconds, min_deficit_bytes, max_bytes_per_run FROM downmask_policy WHERE id=1`).
		Scan(&p.PullMode, &p.Iface, &p.MinRatio, &p.MaxRatio, &p.TimeWindowStart, &p.TimeWindowEnd, &p.MaxJitterSeconds, &minDeficit, &maxRun)
	if err != nil {
		return DownmaskPolicy{}, err
	}
	p.MinDeficitBytes = uint64(minDeficit)
	p.MaxBytesPerRun = uint64(maxRun)
	return p, nil
}

// SaveDownmaskPolicy stores automatic downmask policy.
func (db *DB) SaveDownmaskPolicy(p DownmaskPolicy) error {
	_, err := db.sql.Exec(`UPDATE downmask_policy SET pull_mode=?, iface=?, min_ratio=?, max_ratio=?, time_window_start=?, time_window_end=?, max_jitter_seconds=?, min_deficit_bytes=?, max_bytes_per_run=? WHERE id=1`,
		p.PullMode, p.Iface, p.MinRatio, p.MaxRatio, p.TimeWindowStart, p.TimeWindowEnd, p.MaxJitterSeconds, int64(p.MinDeficitBytes), int64(p.MaxBytesPerRun))
	return err
}

// DownmaskABPullConfig controls AB downmask pull behavior.
type DownmaskABPullConfig struct {
	Protocol           string
	ProtocolMode       string
	TCPEnabled         bool
	UDPEnabled         bool
	RemotePort         int
	LocalIP            string
	Token              string
	SpeedLimit         string
	TimeoutSeconds     int
	ParallelLimit      int
	SpeedJitterPercent int
	BytesJitterPercent int
}

// LoadDownmaskABPullConfig loads AB pull config.
func (db *DB) LoadDownmaskABPullConfig() (DownmaskABPullConfig, error) {
	var cfg DownmaskABPullConfig
	var tcp, udp boolScan
	err := db.sql.QueryRow(`SELECT protocol, protocol_mode, tcp_enabled, udp_enabled, remote_port, local_ip, token, speed_limit, timeout_seconds, parallel_limit, speed_jitter_percent, bytes_jitter_percent FROM downmask_ab_pull_config WHERE id=1`).
		Scan(&cfg.Protocol, &cfg.ProtocolMode, &tcp, &udp, &cfg.RemotePort, &cfg.LocalIP, &cfg.Token, &cfg.SpeedLimit, &cfg.TimeoutSeconds, &cfg.ParallelLimit, &cfg.SpeedJitterPercent, &cfg.BytesJitterPercent)
	if err != nil {
		return DownmaskABPullConfig{}, err
	}
	cfg.TCPEnabled = bool(tcp)
	cfg.UDPEnabled = bool(udp)
	return cfg, nil
}

// SaveDownmaskABPullConfig stores AB pull config.
func (db *DB) SaveDownmaskABPullConfig(cfg DownmaskABPullConfig) error {
	_, err := db.sql.Exec(`UPDATE downmask_ab_pull_config SET protocol=?, protocol_mode=?, tcp_enabled=?, udp_enabled=?, remote_port=?, local_ip=?, token=?, speed_limit=?, timeout_seconds=?, parallel_limit=?, speed_jitter_percent=?, bytes_jitter_percent=? WHERE id=1`,
		cfg.Protocol, cfg.ProtocolMode, boolInt(cfg.TCPEnabled), boolInt(cfg.UDPEnabled), cfg.RemotePort, cfg.LocalIP, cfg.Token, cfg.SpeedLimit, cfg.TimeoutSeconds, cfg.ParallelLimit, cfg.SpeedJitterPercent, cfg.BytesJitterPercent)
	return err
}

// DownmaskABTarget describes one AB pull target.
type DownmaskABTarget struct {
	Host       string
	Port       int
	Token      string
	LocalIP    string
	Weight     int
	TCPEnabled bool
	UDPEnabled bool
}

// LoadDownmaskABTargets loads AB targets ordered by host.
func (db *DB) LoadDownmaskABTargets() ([]DownmaskABTarget, error) {
	rows, err := db.sql.Query(`SELECT host, port, token, local_ip, weight, tcp_enabled, udp_enabled FROM downmask_ab_pull_targets ORDER BY host`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DownmaskABTarget
	for rows.Next() {
		var t DownmaskABTarget
		var tcp, udp boolScan
		if err := rows.Scan(&t.Host, &t.Port, &t.Token, &t.LocalIP, &t.Weight, &tcp, &udp); err != nil {
			return nil, err
		}
		t.TCPEnabled = bool(tcp)
		t.UDPEnabled = bool(udp)
		out = append(out, t)
	}
	return out, rows.Err()
}

// UpsertDownmaskABTarget inserts or updates an AB target.
func (db *DB) UpsertDownmaskABTarget(t DownmaskABTarget) error {
	_, err := db.sql.Exec(`INSERT INTO downmask_ab_pull_targets(host, port, token, local_ip, weight, tcp_enabled, udp_enabled)
		VALUES(?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(host) DO UPDATE SET port=excluded.port, token=excluded.token, local_ip=excluded.local_ip, weight=excluded.weight, tcp_enabled=excluded.tcp_enabled, udp_enabled=excluded.udp_enabled`,
		t.Host, t.Port, t.Token, t.LocalIP, t.Weight, boolInt(t.TCPEnabled), boolInt(t.UDPEnabled))
	return err
}

// DeleteDownmaskABTarget deletes an AB target by host.
func (db *DB) DeleteDownmaskABTarget(host string) (bool, error) {
	res, err := db.sql.Exec(`DELETE FROM downmask_ab_pull_targets WHERE host=?`, host)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// ClearDownmaskABTargets deletes all AB targets.
func (db *DB) ClearDownmaskABTargets() error {
	_, err := db.sql.Exec(`DELETE FROM downmask_ab_pull_targets`)
	return err
}

// DownmaskDayState is persisted automatic pull state for the current day.
type DownmaskDayState struct {
	Date                string
	Iface               string
	TargetRatio         float64
	RXAccum             uint64
	TXAccum             uint64
	LastRXRaw           uint64
	LastTXRaw           uint64
	NextEligibleAt      int64
	PreviousDate        string
	PreviousTargetRatio *float64
	GenerationSource    string
	GeneratedAt         string
	LastAction          string
	LastActualBytes     uint64
	LastPlannedBytes    uint64
	LastError           string
	UpdatedAt           string
}

// LoadDownmaskDayState loads automatic pull day state.
func (db *DB) LoadDownmaskDayState() (DownmaskDayState, bool, error) {
	var s DownmaskDayState
	var rx, tx, lastRX, lastTX, actual, planned int64
	var previous sql.NullFloat64
	err := db.sql.QueryRow(`SELECT date, iface, target_ratio, rx_accum, tx_accum, last_rx_raw, last_tx_raw, next_eligible_at, previous_date, previous_target_ratio, generation_source, generated_at, last_action, last_actual_bytes, last_planned_bytes, last_error, updated_at FROM downmask_day_state WHERE id=1`).
		Scan(&s.Date, &s.Iface, &s.TargetRatio, &rx, &tx, &lastRX, &lastTX, &s.NextEligibleAt, &s.PreviousDate, &previous, &s.GenerationSource, &s.GeneratedAt, &s.LastAction, &actual, &planned, &s.LastError, &s.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return DownmaskDayState{}, false, nil
	}
	if err != nil {
		return DownmaskDayState{}, false, err
	}
	s.RXAccum = uint64(rx)
	s.TXAccum = uint64(tx)
	s.LastRXRaw = uint64(lastRX)
	s.LastTXRaw = uint64(lastTX)
	s.LastActualBytes = uint64(actual)
	s.LastPlannedBytes = uint64(planned)
	if previous.Valid {
		value := previous.Float64
		s.PreviousTargetRatio = &value
	}
	return s, true, nil
}

// SaveDownmaskDayState stores automatic pull day state.
func (db *DB) SaveDownmaskDayState(s DownmaskDayState) error {
	var previous any
	if s.PreviousTargetRatio != nil {
		previous = *s.PreviousTargetRatio
	}
	_, err := db.sql.Exec(`INSERT INTO downmask_day_state(id, date, iface, target_ratio, rx_accum, tx_accum, last_rx_raw, last_tx_raw, next_eligible_at, previous_date, previous_target_ratio, generation_source, generated_at, last_action, last_actual_bytes, last_planned_bytes, last_error, updated_at)
		VALUES(1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET date=excluded.date, iface=excluded.iface, target_ratio=excluded.target_ratio, rx_accum=excluded.rx_accum, tx_accum=excluded.tx_accum,
			last_rx_raw=excluded.last_rx_raw, last_tx_raw=excluded.last_tx_raw, next_eligible_at=excluded.next_eligible_at, previous_date=excluded.previous_date,
			previous_target_ratio=excluded.previous_target_ratio, generation_source=excluded.generation_source, generated_at=excluded.generated_at,
			last_action=excluded.last_action, last_actual_bytes=excluded.last_actual_bytes, last_planned_bytes=excluded.last_planned_bytes, last_error=excluded.last_error, updated_at=excluded.updated_at`,
		s.Date, s.Iface, s.TargetRatio, int64(s.RXAccum), int64(s.TXAccum), int64(s.LastRXRaw), int64(s.LastTXRaw), s.NextEligibleAt, s.PreviousDate, previous,
		s.GenerationSource, s.GeneratedAt, s.LastAction, int64(s.LastActualBytes), int64(s.LastPlannedBytes), s.LastError, s.UpdatedAt)
	return err
}

// DownmaskRatioHistory records daily target-ratio generation history.
type DownmaskRatioHistory struct {
	Date                string
	TargetRatio         float64
	PreviousDate        string
	PreviousTargetRatio *float64
	GenerationSource    string
	GeneratedAt         string
}

// LatestDownmaskRatioHistoryBefore loads the latest history entry before date.
func (db *DB) LatestDownmaskRatioHistoryBefore(date string) (DownmaskRatioHistory, bool, error) {
	row := db.sql.QueryRow(`SELECT date, target_ratio, previous_date, previous_target_ratio, generation_source, generated_at FROM downmask_ratio_history WHERE date < ? ORDER BY date DESC LIMIT 1`, date)
	return scanDownmaskRatioHistory(row)
}

// DownmaskRatioHistoryForDate loads one history entry by date.
func (db *DB) DownmaskRatioHistoryForDate(date string) (DownmaskRatioHistory, bool, error) {
	row := db.sql.QueryRow(`SELECT date, target_ratio, previous_date, previous_target_ratio, generation_source, generated_at FROM downmask_ratio_history WHERE date=?`, date)
	return scanDownmaskRatioHistory(row)
}

func scanDownmaskRatioHistory(row *sql.Row) (DownmaskRatioHistory, bool, error) {
	var h DownmaskRatioHistory
	var previous sql.NullFloat64
	err := row.Scan(&h.Date, &h.TargetRatio, &h.PreviousDate, &previous, &h.GenerationSource, &h.GeneratedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return DownmaskRatioHistory{}, false, nil
	}
	if err != nil {
		return DownmaskRatioHistory{}, false, err
	}
	if previous.Valid {
		value := previous.Float64
		h.PreviousTargetRatio = &value
	}
	return h, true, nil
}

// SaveDownmaskRatioHistory stores one history entry and keeps the latest 32 days.
func (db *DB) SaveDownmaskRatioHistory(h DownmaskRatioHistory) error {
	var previous any
	if h.PreviousTargetRatio != nil {
		previous = *h.PreviousTargetRatio
	}
	tx, err := db.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO downmask_ratio_history(date, target_ratio, previous_date, previous_target_ratio, generation_source, generated_at)
		VALUES(?, ?, ?, ?, ?, ?)
		ON CONFLICT(date) DO UPDATE SET target_ratio=excluded.target_ratio, previous_date=excluded.previous_date,
			previous_target_ratio=excluded.previous_target_ratio, generation_source=excluded.generation_source, generated_at=excluded.generated_at`,
		h.Date, h.TargetRatio, h.PreviousDate, previous, h.GenerationSource, h.GeneratedAt); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM downmask_ratio_history WHERE date NOT IN (SELECT date FROM downmask_ratio_history ORDER BY date DESC LIMIT 32)`); err != nil {
		return err
	}
	return tx.Commit()
}

type boolScan bool

func (b *boolScan) Scan(value any) error {
	switch v := value.(type) {
	case bool:
		*b = boolScan(v)
	case int64:
		*b = boolScan(v != 0)
	case []byte:
		*b = boolScan(string(v) != "0")
	case string:
		*b = boolScan(v != "0")
	default:
		return fmt.Errorf("unsupported bool value %T", value)
	}
	return nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
