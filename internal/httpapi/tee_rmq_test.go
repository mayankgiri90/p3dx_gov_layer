package httpapi

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/config"
)

func TestNewTEEJobID(t *testing.T) {
	format := regexp.MustCompile(`^job-[0-9a-f]{12}$`)
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id, err := newTEEJobID()
		if err != nil {
			t.Fatal(err)
		}
		if !format.MatchString(id) {
			t.Fatalf("newTEEJobID() = %q, want job-<12 hex>", id)
		}
		if seen[id] {
			t.Fatalf("newTEEJobID() repeated %q", id)
		}
		seen[id] = true
	}
}

func TestTEERunRequestJSON(t *testing.T) {
	at := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	b, err := json.Marshal(teeRunRequest{Type: "tee-run-request", JobID: "job-0123456789ab", ContractID: "c-1",
		ContractHash: "h", RequestedAt: at, SubContract: map[string]string{"k": "v"}})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	// The orchestrator reads these field names.
	for k, want := range map[string]interface{}{"type": "tee-run-request", "jobId": "job-0123456789ab",
		"contractId": "c-1", "contractHash": "h", "requestedAt": "2026-11-03T10:00:00Z"} {
		if got[k] != want {
			t.Errorf("%s = %v, want %v", k, got[k], want)
		}
	}
	if _, ok := got["jobRef"]; ok {
		t.Errorf("empty jobRef should be omitted: %s", b)
	}
	if sub, _ := got["subContract"].(map[string]interface{}); sub["k"] != "v" {
		t.Errorf("subContract = %v", got["subContract"])
	}
}

func TestPublishTEERequestErrors(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	msg := teeRunRequest{Type: "tee-run-request", JobID: "job-0123456789ab"}

	s := newTestServer(&config.Config{})
	if err := s.publishTEERequest(ctx, msg); err == nil || !strings.Contains(err.Error(), "RMQ_URL") {
		t.Errorf("no RMQ_URL: err = %v, want RMQ_URL is not set", err)
	}

	// Nothing listens on port 1: the dial fails and is reported as a connect error.
	s = newTestServer(&config.Config{RMQURL: "amqp://guest:guest@127.0.0.1:1/"})
	if err := s.publishTEERequest(ctx, msg); err == nil || !strings.HasPrefix(err.Error(), "connect:") {
		t.Errorf("unreachable broker: err = %v, want connect: ...", err)
	}
}

func TestResultReadURLForJobWithoutDB(t *testing.T) {
	s := newTestServer(&config.Config{ResultReadURL: "https://read/default"})
	if got := s.resultReadURLForJob(context.Background(), "job-0123456789ab"); got != "https://read/default" {
		t.Errorf("resultReadURLForJob without a db = %q, want RESULT_READ_URL", got)
	}
}
