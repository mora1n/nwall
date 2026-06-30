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
	return db.ensureDefaults(ctx)
}

func (db *DB) migrateLeaseTCPOnly(ctx context.Context) error {
	if err := db.ensureColumn(ctx, "lease_config", "lease_key", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	return db.ensureColumn(ctx, "lease_routes", "idle_ttl", "TEXT NOT NULL DEFAULT ''")
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
	if _, err := db.sql.ExecContext(ctx, `INSERT OR IGNORE INTO lease_trigger_config(id, listen_host, listen_port) VALUES(1, ?, ?)`,
		cfg.LeaseTrigger.ListenHost, cfg.LeaseTrigger.ListenPort); err != nil {
		return err
	}
	if _, err := db.sql.ExecContext(ctx, `INSERT OR IGNORE INTO downmask_config(id, tcp_addr, udp_addr, token, max_rate, udp_payload_bytes) VALUES(1, '', '', '', 0, 1200)`); err != nil {
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
	if err := db.sql.QueryRow(`SELECT listen_host, listen_port FROM lease_trigger_config WHERE id=1`).
		Scan(&cfg.LeaseTrigger.ListenHost, &cfg.LeaseTrigger.ListenPort); err != nil {
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
	if _, err := tx.Exec(`UPDATE lease_trigger_config SET listen_host=?, listen_port=? WHERE id=1`,
		cfg.ListenHost, cfg.ListenPort); err != nil {
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
	MaxRate         uint64
	UDPPayloadBytes int
}

// LoadDownmaskConfig loads downmask server configuration.
func (db *DB) LoadDownmaskConfig() (DownmaskConfig, error) {
	var cfg DownmaskConfig
	var maxRate int64
	if err := db.sql.QueryRow(`SELECT tcp_addr, udp_addr, token, max_rate, udp_payload_bytes FROM downmask_config WHERE id=1`).
		Scan(&cfg.TCPAddr, &cfg.UDPAddr, &cfg.Token, &maxRate, &cfg.UDPPayloadBytes); err != nil {
		return DownmaskConfig{}, err
	}
	cfg.MaxRate = uint64(maxRate)
	return cfg, nil
}

// SaveDownmaskConfig stores downmask server configuration.
func (db *DB) SaveDownmaskConfig(cfg DownmaskConfig) error {
	_, err := db.sql.Exec(`UPDATE downmask_config SET tcp_addr=?, udp_addr=?, token=?, max_rate=?, udp_payload_bytes=? WHERE id=1`,
		cfg.TCPAddr, cfg.UDPAddr, cfg.Token, int64(cfg.MaxRate), cfg.UDPPayloadBytes)
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
