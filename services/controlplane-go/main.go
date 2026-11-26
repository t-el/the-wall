package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

// Control Plane - GRC, Audit, Log Retention
// Loi 05-20 Art. 26: 1-year append-only, tamper-evident logs
// Consumes remediation events from data plane via NATS

type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	TenantID  string    `json:"tenant_id"`
	EventType string    `json:"event_type"`
	Message   string    `json:"message"`
	PrevHash  string    `json:"prev_hash"`
	Hash      string    `json:"hash"`
	Class     string    `json:"dnssi_class,omitempty"`
}

type AppendOnlyLog struct {
	mu       sync.Mutex
	entries  []LogEntry
	lastHash string
}

func NewAppendOnlyLog() *AppendOnlyLog {
	return &AppendOnlyLog{
		entries:  make([]LogEntry, 0),
		lastHash: "genesis",
	}
}

func (l *AppendOnlyLog) Append(tenantID, eventType, message, class string) LogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry := LogEntry{
		Timestamp: time.Now().UTC(),
		TenantID:  tenantID,
		EventType: eventType,
		Message:   message,
		PrevHash:  l.lastHash,
		Class:     class,
	}

	data, _ := json.Marshal(entry)
	hash := sha256.Sum256(data)
	entry.Hash = hex.EncodeToString(hash[:])
	l.lastHash = entry.Hash
	l.entries = append(l.entries, entry)
	return entry
}

func (l *AppendOnlyLog) VerifyChain() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	prev := "genesis"
	for _, e := range l.entries {
		if e.PrevHash != prev {
			return false
		}
		prev = e.Hash
	}
	return true
}

type ControlPlane struct {
	log *AppendOnlyLog
}

func NewControlPlane() *ControlPlane {
	return &ControlPlane{log: NewAppendOnlyLog()}
}

func (cp *ControlPlane) HandleRemediation(msg *nats.Msg) {
	var payload map[string]interface{}
	if err := json.Unmarshal(msg.Data, &payload); err != nil {
		log.Printf("invalid remediation payload: %v", err)
		return
	}

	tenantID, _ := payload["tenant_id"].(string)
	if tenantID == "" {
		tenantID = "default"
	}
	class, _ := payload["asset_class"].(string)
	if class == "" {
		class = "B"
	}
	playbooks, _ := payload["playbooks"].([]interface{})
	severity, _ := payload["severity"].(string)

	msgText := fmt.Sprintf("Threat contained — severity=%s playbooks=%v", severity, playbooks)
	entry := cp.log.Append(tenantID, "remediation", msgText, class)
	log.Printf("Logged remediation for %s (class %s, hash %s)", tenantID, class, entry.Hash[:12])
}

func main() {
	fmt.Println("The Wall Control Plane starting...")
	cp := NewControlPlane()

	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = nats.DefaultURL
	}

	nc, err := nats.Connect(natsURL)
	if err != nil {
		log.Fatalf("NATS connect: %v", err)
	}
	defer nc.Close()

	_, err = nc.Subscribe("thewall.remediation", cp.HandleRemediation)
	if err != nil {
		log.Fatalf("subscribe: %v", err)
	}
	log.Println("Subscribed to thewall.remediation — append-only log active")

	select {}
}
