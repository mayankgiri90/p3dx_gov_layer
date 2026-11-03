package config

// per-workload result URLs, read from the environment at use.

import (
	"os"
	"strings"
)

func workloadEnvKey(workload string) string {
	return strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(strings.TrimSpace(workload)))
}

// ResultURLFor is RESULT_URL_<WORKLOAD> if set, else DEFAULT_RESULT_URL.
func (c *Config) ResultURLFor(workload string) string {
	if k := workloadEnvKey(workload); k != "" {
		if v := strings.TrimSpace(os.Getenv("RESULT_URL_" + k)); v != "" {
			return v
		}
	}
	return c.DefaultResultURL
}

// ResultReadURLFor is RESULT_READ_URL_<WORKLOAD> if set, else RESULT_READ_URL.
func (c *Config) ResultReadURLFor(workload string) string {
	if k := workloadEnvKey(workload); k != "" {
		if v := strings.TrimSpace(os.Getenv("RESULT_READ_URL_" + k)); v != "" {
			return v
		}
	}
	return c.ResultReadURL
}
