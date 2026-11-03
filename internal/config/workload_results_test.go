package config

import "testing"

func TestWorkloadEnvKey(t *testing.T) {
	cases := map[string]string{
		"market-offer-generation": "MARKET_OFFER_GENERATION",
		" credits.evaluation ":    "CREDITS_EVALUATION",
		"Mixed-Case":              "MIXED_CASE",
		"":                        "",
	}
	for in, want := range cases {
		if got := workloadEnvKey(in); got != want {
			t.Errorf("workloadEnvKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResultURLFor(t *testing.T) {
	c := &Config{DefaultResultURL: "https://blob/default", ResultReadURL: "https://read/default"}
	t.Setenv("RESULT_URL_MARKET_OFFER_GENERATION", " https://blob/market ")
	t.Setenv("RESULT_READ_URL_MARKET_OFFER_GENERATION", "https://read/market")
	t.Setenv("RESULT_URL_CREDITS_EVALUATION", "   ")

	if got := c.ResultURLFor("market-offer-generation"); got != "https://blob/market" {
		t.Errorf("ResultURLFor(market-offer-generation) = %q, want the per-workload URL", got)
	}
	if got := c.ResultReadURLFor("market-offer-generation"); got != "https://read/market" {
		t.Errorf("ResultReadURLFor(market-offer-generation) = %q, want the per-workload URL", got)
	}
	// Blank or unset per-workload values fall back to the defaults.
	for _, w := range []string{"credits-evaluation", "unknown", ""} {
		if got := c.ResultURLFor(w); got != c.DefaultResultURL {
			t.Errorf("ResultURLFor(%q) = %q, want DEFAULT_RESULT_URL", w, got)
		}
		if got := c.ResultReadURLFor(w); got != c.ResultReadURL {
			t.Errorf("ResultReadURLFor(%q) = %q, want RESULT_READ_URL", w, got)
		}
	}
}

func TestTEEDispatchDefaults(t *testing.T) {
	for _, k := range []string{"TEE_DISPATCH", "RMQ_URL", "RMQ_TEE_EXCHANGE", "RMQ_TEE_ROUTING_KEY"} {
		t.Setenv(k, "")
	}
	c := Load()
	if c.TEEDispatch != "grpc" || c.RMQURL != "" || c.RMQTEEExchange != "tee" || c.RMQTEERoutingKey != "tee-request" {
		t.Errorf("defaults = %q %q %q %q, want grpc, empty, tee, tee-request",
			c.TEEDispatch, c.RMQURL, c.RMQTEEExchange, c.RMQTEERoutingKey)
	}

	t.Setenv("TEE_DISPATCH", "rmq")
	t.Setenv("RMQ_URL", "amqp://u:p@rmq:5672/")
	t.Setenv("RMQ_TEE_EXCHANGE", "x")
	t.Setenv("RMQ_TEE_ROUTING_KEY", "k")
	c = Load()
	if c.TEEDispatch != "rmq" || c.RMQURL != "amqp://u:p@rmq:5672/" || c.RMQTEEExchange != "x" || c.RMQTEERoutingKey != "k" {
		t.Errorf("from env = %q %q %q %q", c.TEEDispatch, c.RMQURL, c.RMQTEEExchange, c.RMQTEERoutingKey)
	}
}
