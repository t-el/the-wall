package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// Control Plane — persistent, hash-chained, multi-tenant log store
// Loi 05-20 Art. 26 (365-day append-only)

type LogEntry struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	TenantID  string    `json:"tenant_id"`
	EventType string    `json:"event_type"`
	Message   string    `json:"message"`
	PrevHash  string    `json:"prev_hash"`
	Hash      string    `json:"hash"`
	Class     string    `json:"dnssi_class"`
}

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, err
	}
	s := &Store{pool: pool}
	if err := s.migrate(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS audit_log (
			id          BIGSERIAL PRIMARY KEY,
			ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
			tenant_id   TEXT NOT NULL,
			event_type  TEXT NOT NULL,
			message     TEXT NOT NULL,
			prev_hash   TEXT NOT NULL,
			hash        TEXT NOT NULL,
			dnssi_class TEXT NOT NULL DEFAULT 'B'
		);
		CREATE INDEX IF NOT EXISTS audit_log_tenant_ts ON audit_log (tenant_id, ts DESC);
	`)
	return err
}

func (s *Store) Append(ctx context.Context, tenantID, eventType, message, class string) (LogEntry, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LogEntry{}, err
	}
	defer tx.Rollback(ctx)

	var prev string
	err = tx.QueryRow(ctx,
		`SELECT hash FROM audit_log WHERE tenant_id = $1 ORDER BY id DESC LIMIT 1`,
		tenantID).Scan(&prev)
	if err == sql.ErrNoRows || (err != nil && err.Error() == "no rows in result set") {
		prev = "genesis"
	} else if err != nil {
		return LogEntry{}, err
	}

	entry := LogEntry{
		Timestamp: time.Now().UTC(),
		TenantID:  tenantID,
		EventType: eventType,
		Message:   message,
		PrevHash:  prev,
		Class:     class,
	}
	data, _ := json.Marshal(entry)
	sum := sha256.Sum256(data)
	entry.Hash = hex.EncodeToString(sum[:])

	err = tx.QueryRow(ctx, `
		INSERT INTO audit_log (ts, tenant_id, event_type, message, prev_hash, hash, dnssi_class)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id`,
		entry.Timestamp, entry.TenantID, entry.EventType, entry.Message,
		entry.PrevHash, entry.Hash, entry.Class).Scan(&entry.ID)
	if err != nil {
		return LogEntry{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LogEntry{}, err
	}
	return entry, nil
}

func (s *Store) Close() { s.pool.Close() }

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}
	store, err := NewStore(ctx, dsn)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer store.Close()
	log.Println("TimescaleDB / PostgreSQL audit store ready")

	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = nats.DefaultURL
	}
	nc, err := nats.Connect(natsURL)
	if err != nil {
		log.Fatalf("nats: %v", err)
	}
	defer nc.Close()

	_, err = nc.Subscribe("thewall.remediation", func(msg *nats.Msg) {
		var p map[string]interface{}
		if err := json.Unmarshal(msg.Data, &p); err != nil {
			log.Printf("bad payload: %v", err)
			return
		}
		tenant, _ := p["tenant_id"].(string)
		if tenant == "" {
			tenant = "default"
		}
		class, _ := p["asset_class"].(string)
		if class == "" {
			class = "B"
		}
		sev, _ := p["severity"].(string)
		pb, _ := p["playbooks"].([]interface{})
		text := fmt.Sprintf("contained severity=%s playbooks=%v", sev, pb)

		entry, err := store.Append(context.Background(), tenant, "remediation", text, class)
		if err != nil {
			log.Printf("append failed: %v", err)
			return
		}
		log.Printf("logged id=%d tenant=%s hash=%s", entry.ID, tenant, entry.Hash[:12])
	})
	if err != nil {
		log.Fatalf("subscribe: %v", err)
	}
	log.Println("control plane listening on thewall.remediation")

	<-ctx.Done()
	log.Println("shutting down")
}
