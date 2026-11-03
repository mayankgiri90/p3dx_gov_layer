package httpapi

// View Result reads the result URL of the job's workload.

import (
	"context"

	"github.com/s4r4v4n04/p3dx_gov_layer/internal/db"
)

// resultReadURLForJob finds the contract whose run_started event names this coordinator job and returns its
// workload's read URL; RESULT_READ_URL when the job or contract is unknown.
func (s *Server) resultReadURLForJob(ctx context.Context, jobID string) string {
	if s.db == nil {
		return s.cfg.ResultReadURL
	}
	var contractID string
	err := s.db.Pool.QueryRow(ctx, `SELECT contract_id FROM contract_events
		WHERE event = $1 AND strpos(detail, '(coordinator job ' || $2 || ')') > 0
		ORDER BY created_at DESC LIMIT 1`, db.ContractEventRunStarted, jobID).Scan(&contractID)
	if err != nil || contractID == "" {
		return s.cfg.ResultReadURL
	}
	c, err := s.loadContract(ctx, contractID)
	if err != nil || c == nil || len(c.Parties.ApplicationProviders) == 0 {
		return s.cfg.ResultReadURL
	}
	return s.cfg.ResultReadURLFor(c.Parties.ApplicationProviders[0].ID)
}
