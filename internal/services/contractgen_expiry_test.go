package services

import (
	"testing"
	"time"
)

func TestDatasetsValidUntil(t *testing.T) {
	limit := time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC)
	early := time.Date(2026, 12, 1, 0, 0, 0, 0, time.FixedZone("IST", 5*3600+1800))
	earlier := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	late := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		name string
		ds   []DatasetInput
		want time.Time
	}{
		{"no datasets", nil, limit},
		{"no expiry", []DatasetInput{{DatasetID: "a"}}, limit},
		{"expiry after the limit", []DatasetInput{{DatasetID: "a", ExpiresAt: &late}}, limit},
		{"expiry before the limit", []DatasetInput{{DatasetID: "a", ExpiresAt: &early}}, early.UTC()},
		{"earliest of several", []DatasetInput{{ExpiresAt: &early}, {}, {ExpiresAt: &earlier}, {ExpiresAt: &late}}, earlier},
	}
	for _, c := range cases {
		got := datasetsValidUntil(c.ds, limit)
		if !got.Equal(c.want) {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
		if got.Location() != time.UTC {
			t.Errorf("%s: got location %s, want UTC", c.name, got.Location())
		}
	}
}

func TestBuildGeneratedContractValidUntil(t *testing.T) {
	// Without a policy expiry the contract runs the default 90 days.
	c := BuildGeneratedContract(GenerateContractInput{Datasets: []DatasetInput{{DatasetID: "d1"}}})
	if d := time.Until(c.Lifecycle.ValidUntil); d < 89*24*time.Hour || d > 90*24*time.Hour {
		t.Errorf("no expiry: valid_until in %s, want ~90 days", d)
	}

	// A provider's "Expires on" inside those 90 days ends the contract on that date.
	exp := time.Now().Add(10 * 24 * time.Hour).UTC().Truncate(time.Second)
	c = BuildGeneratedContract(GenerateContractInput{Datasets: []DatasetInput{{DatasetID: "d1", ExpiresAt: &exp}}})
	if !c.Lifecycle.ValidUntil.Equal(exp) {
		t.Errorf("with expiry: valid_until = %s, want %s", c.Lifecycle.ValidUntil, exp)
	}
}
