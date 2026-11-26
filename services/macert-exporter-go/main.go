package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/nats-io/nats.go"
)

// maCERT Incident Dispatcher
// Loi 05-20 Art. 8, 30, 33 — automated escalation
// Consumes remediation events from data plane via NATS

type MaCertAlert struct {
	IncidentID         string    `json:"incident_id"`
	Timestamp          time.Time `json:"timestamp"`
	TechnicalVector    string    `json:"technical_vector"`
	AffectedAssetClass string    `json:"affected_asset_class"`
	RemediationStatus  string    `json:"remediation_status"`
	TenantID           string    `json:"tenant_id"`
	Severity           string    `json:"severity"`
	Playbooks          []string  `json:"playbooks,omitempty"`
}

func dispatch(alert MaCertAlert) {
	payload, err := json.MarshalIndent(alert, "", "  ")
	if err != nil {
		log.Printf("marshal alert: %v", err)
		return
	}
	log.Println("--- maCERT Alert (Loi 05-20 Art. 8/30/33) ---")
	log.Println(string(payload))
	log.Println("--- End alert (production: mTLS POST to maCERT) ---")
}

func handleRemediation(msg *nats.Msg) {
	var payload map[string]interface{}
	if err := json.Unmarshal(msg.Data, &payload); err != nil {
		log.Printf("invalid payload: %v", err)
		return
	}

	requires, _ := payload["requires_macert"].(bool)
	if !requires {
		return
	}

	tenantID, _ := payload["tenant_id"].(string)
	class, _ := payload["asset_class"].(string)
	severity, _ := payload["severity"].(string)
	playbooksRaw, _ := payload["playbooks"].([]interface{})

	var playbooks []string
	for _, p := range playbooksRaw {
		if s, ok := p.(string); ok {
			playbooks = append(playbooks, s)
		}
	}

	vector := "DGSSI marker / playbook match"
	if len(playbooks) > 0 {
		vector = fmt.Sprintf("Playbooks: %v", playbooks)
	}

	alert := MaCertAlert{
		IncidentID:         fmt.Sprintf("INC-%d", time.Now().UnixNano()),
		Timestamp:          time.Now().UTC(),
		TechnicalVector:    vector,
		AffectedAssetClass: class,
		RemediationStatus:  "contained_by_dataplane",
		TenantID:           tenantID,
		Severity:           severity,
		Playbooks:          playbooks,
	}

	dispatch(alert)
}

func main() {
	fmt.Println("maCERT Exporter starting...")

	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = nats.DefaultURL
	}

	nc, err := nats.Connect(natsURL)
	if err != nil {
		log.Fatalf("NATS connect: %v", err)
	}
	defer nc.Close()

	_, err = nc.Subscribe("thewall.remediation", handleRemediation)
	if err != nil {
		log.Fatalf("subscribe: %v", err)
	}
	log.Println("Subscribed to thewall.remediation — maCERT escalation active")

	select {}
}
