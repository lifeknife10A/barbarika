package egress

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"barbarika-agent/pkg/crypto"
	"barbarika-agent/pkg/models"
)

// TestHeartbeatConformsToJashSchema checks that the heartbeat the agent (Anay)
// serializes satisfies the shared transport contract Jash owns
// (transport/heartbeat.schema.json). This keeps all three components in sync:
// the agent's wire bytes must match the schema Sentry validates against.
func TestHeartbeatConformsToJashSchema(t *testing.T) {
	schemaPath := filepath.Join("..", "..", "..", "..", "transport", "heartbeat.schema.json")
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Skipf("Jash's transport schema not found (%s); skipping cross-component check", schemaPath)
	}

	var schema struct {
		Required   []string `json:"required"`
		Properties map[string]struct {
			Pattern string      `json:"pattern"`
			Const   interface{} `json:"const"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("parse schema: %v", err)
	}

	// Build a heartbeat exactly as HeartbeatWatcher does before the first event:
	// last_event_hash is the schema-valid zero digest, signature is a real
	// 64-byte Ed25519 signature (base64), agent_health is "healthy".
	signer, err := crypto.NewSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	hb := &models.HeartbeatPayload{
		AgentID:           "primary-srv-01",
		BootID:            "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
		Sequence:          1,
		SentAtUTC:         time.Now().UTC().Format(time.RFC3339),
		LastEventSequence: 0,
		LastEventHash:     zeroHash,
		AgentHealth:       "healthy",
		Signature:         signer.Sign([]byte("heartbeat-preimage")),
	}

	var got map[string]interface{}
	blob, _ := json.Marshal(hb)
	if err := json.Unmarshal(blob, &got); err != nil {
		t.Fatalf("re-parse heartbeat json: %v", err)
	}

	// 1. Every schema-required field is present.
	for _, key := range schema.Required {
		if _, ok := got[key]; !ok {
			t.Errorf("heartbeat missing schema-required field %q", key)
		}
	}

	// 2. Pattern / const constraints the schema declares.
	check := func(field string) {
		spec, ok := schema.Properties[field]
		if !ok {
			return
		}
		val, _ := got[field].(string)
		if spec.Pattern != "" {
			if !regexp.MustCompile(spec.Pattern).MatchString(val) {
				t.Errorf("field %q=%q violates schema pattern %q", field, val, spec.Pattern)
			}
		}
		if spec.Const != nil && val != spec.Const {
			t.Errorf("field %q=%q must equal const %v", field, val, spec.Const)
		}
	}
	check("last_event_hash")
	check("signature")
	check("agent_health")
	check("sent_at_utc")
}
