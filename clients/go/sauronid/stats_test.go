package sauronid

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func validSubmission() StatsSubmission {
	return StatsSubmission{
		TenantID:     "tenant-1",
		MetricID:     "actions_total",
		ClaimedValue: 42,
		NRecords:     7,
		PeriodStart:  1_000,
		PeriodEnd:    2_000,
		MerkleRoot:   "0xabc",
		ProofB64:     "Zm9v",
		VkID:         "StatsHonestComputation.dev.vk@v1",
		CheckpointID: "zkc_test",
		PublicInputs: []string{"42"},
	}
}

func TestSubmitStats_Happy(t *testing.T) {
	var calls int32
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/stats/submit", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		body, _ := io.ReadAll(r.Body)
		var got StatsSubmission
		if err := json.Unmarshal(body, &got); err != nil {
			t.Errorf("invalid body: %v", err)
		}
		if got.TenantID != "tenant-1" {
			t.Errorf("tenant_id mismatch: %s", got.TenantID)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(SubmitResponse{
			Stored: true, LatencyMsVerify: 5, StatementHash: "0xfeed",
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(ClientOptions{BaseURL: srv.URL, AdminKey: "k"})
	resp, err := c.SubmitStats(context.Background(), validSubmission())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Stored {
		t.Fatalf("expected stored=true, got %+v", resp)
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("expected 1 call")
	}
}

func TestSubmitStats_Idempotent(t *testing.T) {
	// Server replies with the same anchored hash for repeated submissions.
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/stats/submit", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(SubmitResponse{
			Stored: true, StatementHash: "0xidempotent",
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(ClientOptions{BaseURL: srv.URL})
	r1, err := c.SubmitStats(context.Background(), validSubmission())
	if err != nil {
		t.Fatal(err)
	}
	r2, err := c.SubmitStats(context.Background(), validSubmission())
	if err != nil {
		t.Fatal(err)
	}
	if r1.StatementHash != r2.StatementHash {
		t.Fatalf("expected matching hashes: %s vs %s", r1.StatementHash, r2.StatementHash)
	}
}

func TestSubmitStats_Validation(t *testing.T) {
	c := NewClient(ClientOptions{BaseURL: "http://example.invalid"})
	cases := []struct {
		name    string
		mutate  func(*StatsSubmission)
	}{
		{"missing tenant", func(s *StatsSubmission) { s.TenantID = "" }},
		{"missing metric", func(s *StatsSubmission) { s.MetricID = "" }},
		{"period inverted", func(s *StatsSubmission) { s.PeriodStart = s.PeriodEnd }},
		{"missing root", func(s *StatsSubmission) { s.MerkleRoot = "" }},
		{"missing proof", func(s *StatsSubmission) { s.ProofB64 = "" }},
		{"missing vk", func(s *StatsSubmission) { s.VkID = "" }},
		{"zero records", func(s *StatsSubmission) { s.NRecords = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := validSubmission()
			tc.mutate(&s)
			_, err := c.SubmitStats(context.Background(), s)
			if !errors.Is(err, ErrInvalidStatsSubmission) {
				t.Fatalf("expected validation error, got %v", err)
			}
		})
	}
}
