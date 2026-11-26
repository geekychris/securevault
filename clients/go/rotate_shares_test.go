package securevault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_RotateShares(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/sys/rotate-shares" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("X-Vault-Token") != "s.test-token" {
			t.Fatalf("expected X-Vault-Token header, got %q", r.Header.Get("X-Vault-Token"))
		}

		var body map[string]int
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}
		if body["new_secret_shares"] != 5 || body["new_secret_threshold"] != 3 {
			t.Fatalf("unexpected request body: %+v", body)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RotateSharesResponse{
			Keys:      []string{"a1", "b2", "c3", "d4", "e5"},
			Threshold: 3,
			NumShares: 5,
		})
	}))
	defer ts.Close()

	client, err := NewClient(ts.URL, "s.test-token")
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	resp, err := client.RotateShares(context.Background(), 5, 3)
	if err != nil {
		t.Fatalf("RotateShares returned error: %v", err)
	}

	if resp.Threshold != 3 || resp.NumShares != 5 {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if len(resp.Keys) != 5 {
		t.Fatalf("expected 5 keys, got %d", len(resp.Keys))
	}
}
