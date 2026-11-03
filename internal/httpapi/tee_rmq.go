package httpapi

// Run TEE through RabbitMQ (TEE_DISPATCH=rmq): runTEEJob hands the gated sub-contract to
// queueTEEJob, which publishes it to the tee-request queue for the orchestrator to consume.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/contract"
	"github.com/s4r4v4n04/p3dx_gov_layer/internal/db"
)

// teeRunRequest is the message on the tee-request queue. The orchestrator must create the coordinator job with JobID.
type teeRunRequest struct {
	Type         string      `json:"type"` // "tee-run-request"
	JobID        string      `json:"jobId"`
	ContractID   string      `json:"contractId"`
	ContractHash string      `json:"contractHash"`
	JobRef       string      `json:"jobRef,omitempty"` // gov_layer job (approval flow), if any
	RequestedAt  time.Time   `json:"requestedAt"`
	SubContract  interface{} `json:"subContract"` // the CreateJob request body (contract.NewSubContract)
}

// newTEEJobID returns a coordinator-style job ID ("job-9f3c4952e83e").
func newTEEJobID() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "job-" + hex.EncodeToString(b), nil
}

// publishTEERequest publishes msg (persistent, mandatory) and waits for the broker's confirm.
func (s *Server) publishTEERequest(ctx context.Context, msg teeRunRequest) error {
	if s.cfg.RMQURL == "" {
		return errors.New("RMQ_URL is not set")
	}
	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	conn, err := amqp.DialConfig(s.cfg.RMQURL, amqp.Config{
		Dial:       amqp.DefaultDial(10 * time.Second),
		Properties: amqp.Table{"connection_name": "p3dx-gov-layer tee-run"},
	})
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()
	ch, err := conn.Channel()
	if err != nil {
		return fmt.Errorf("channel: %w", err)
	}
	defer ch.Close()
	if err := ch.Confirm(false); err != nil {
		return fmt.Errorf("confirm mode: %w", err)
	}
	// A mandatory message that reaches no queue comes back as basic.return, before its confirm.
	returns := ch.NotifyReturn(make(chan amqp.Return, 1))
	dc, err := ch.PublishWithDeferredConfirmWithContext(ctx, s.cfg.RMQTEEExchange, s.cfg.RMQTEERoutingKey, true, false,
		amqp.Publishing{
			ContentType:   "application/json",
			DeliveryMode:  amqp.Persistent,
			MessageId:     msg.JobID,
			CorrelationId: msg.ContractID,
			Type:          msg.Type,
			AppId:         "p3dx-gov-layer",
			Timestamp:     msg.RequestedAt,
			Body:          body,
		})
	if err != nil {
		return fmt.Errorf("publish: %w", err)
	}
	acked, err := dc.WaitContext(ctx)
	if err != nil {
		return fmt.Errorf("confirm: %w", err)
	}
	if !acked {
		return errors.New("broker refused the message (nack)")
	}
	select {
	case ret := <-returns:
		return fmt.Errorf("unroutable: %d %s (exchange %q, routing key %q)", ret.ReplyCode, ret.ReplyText, ret.Exchange, ret.RoutingKey)
	default:
	}
	return nil
}

// queueTEEJob is runTEEJob's TEE_DISPATCH=rmq ending: publish, record run_started, answer JOB_STATE_QUEUED.
func (s *Server) queueTEEJob(w http.ResponseWriter, r *http.Request, c *contract.Contract, sub interface{}) {
	jobID, err := newTEEJobID()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, j{"status": "FAILED", "error": "INTERNAL_ERROR", "message": err.Error()})
		return
	}
	msg := teeRunRequest{Type: "tee-run-request", JobID: jobID, ContractID: c.ContractID, ContractHash: c.ContractHash,
		JobRef: c.JobID, RequestedAt: time.Now().UTC(), SubContract: sub}
	ctx, cancel := context.WithTimeout(reqCtx(r), 30*time.Second)
	defer cancel()
	if err := s.publishTEERequest(ctx, msg); err != nil {
		log.Printf("[TEE-RUN] contract %s: queueing job %s failed: %v", c.ContractID, jobID, err)
		s.recordContractEvent(reqCtx(r), c, db.ContractEventRunFailed, "Run could not be queued: "+err.Error(), "governance-layer")
		writeJSON(w, http.StatusBadGateway, j{"status": "FAILED", "error": "RMQ_PUBLISH_FAILED", "message": err.Error(), "subContract": sub})
		return
	}
	log.Printf("[TEE-RUN] contract %s: queued job %s on exchange %q routing key %q", c.ContractID, jobID,
		s.cfg.RMQTEEExchange, s.cfg.RMQTEERoutingKey)

	if err := s.db.MarkContractTEEEnabled(reqCtx(r), c.ContractID); err != nil {
		log.Printf("[TEE-RUN] Warning: contract %s not marked live: %v", c.ContractID, err)
	}
	if c.JobID != "" {
		s.markJobParticipants(reqCtx(r), c.JobID, db.ParticipantStatusTEEEnabled)
	}
	// "(coordinator job X)" is what the outcome watcher (and its resume after a restart) keys on.
	s.recordContractEvent(reqCtx(r), c, db.ContractEventRunStarted, "TEE run queued (coordinator job "+jobID+")", "governance-layer")
	go s.watchTEERun(jobID)

	writeJSON(w, http.StatusOK, j{"status": "SUCCESS", "subContract": sub, "queued": true,
		"job": j{"jobId": jobID, "contractId": c.ContractID, "state": "JOB_STATE_QUEUED", "createdAt": msg.RequestedAt}})
}
