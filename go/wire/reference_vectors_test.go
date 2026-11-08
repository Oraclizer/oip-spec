package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// These are byte and cryptographic checks, not a Go reference-authority API.
// Keep JSON as raw bytes so integers above 2^53 never pass through float64.
func TestReferenceSigningInputVectors(t *testing.T) {
	type input struct {
		ID        string  `json:"id"`
		Domain    string  `json:"domain"`
		JSON      string  `json:"json_utf8"`
		Hex       string  `json:"input_hex"`
		SHA256    string  `json:"sha256"`
		Key       *string `json:"public_key"`
		Signature *string `json:"signature"`
	}
	var vectors struct {
		Format      int     `json:"format"`
		Inputs      []input `json:"vectors"`
		Certificate struct {
			JSON   string `json:"json_utf8"`
			Hex    string `json:"hex"`
			SHA256 string `json:"sha256"`
		} `json:"source_certificate"`
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "vectors", "reference-signing-inputs.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Format != 1 || len(vectors.Inputs) != 12 {
		t.Fatal("reference domains are incomplete")
	}
	byID := map[string]input{}
	for _, row := range vectors.Inputs {
		if _, exists := byID[row.ID]; exists {
			t.Fatalf("duplicate vector %s", row.ID)
		}
		byID[row.ID] = row
		exact, err := hex.DecodeString(row.Hex)
		if err != nil {
			t.Fatal(err)
		}
		if !json.Valid([]byte(row.JSON)) || !bytes.Equal(exact, append(append([]byte(row.Domain), 0), []byte(row.JSON)...)) {
			t.Fatalf("%s: domain or compact JSON differs", row.ID)
		}
		digest := sha256.Sum256(exact)
		if hex.EncodeToString(digest[:]) != row.SHA256 {
			t.Fatalf("%s: digest", row.ID)
		}
		if row.Key != nil && row.Signature != nil {
			key, err := hex.DecodeString(*row.Key)
			if err != nil || len(key) != 32 {
				t.Fatalf("%s: key", row.ID)
			}
			signature, err := hex.DecodeString(*row.Signature)
			if err != nil || !verify([32]byte(key), exact, signature) {
				t.Fatalf("%s: signature", row.ID)
			}
			signature[0] ^= 1
			if verify([32]byte(key), exact, signature) {
				t.Fatalf("%s: changed signature", row.ID)
			}
		} else if row.Key != nil || row.Signature != nil {
			t.Fatalf("%s: incomplete signature", row.ID)
		}
	}
	certificate, err := hex.DecodeString(vectors.Certificate.Hex)
	if err != nil || !bytes.Equal(certificate, []byte(vectors.Certificate.JSON)) {
		t.Fatal("certificate bytes")
	}
	digest := sha256.Sum256(certificate)
	if hex.EncodeToString(digest[:]) != vectors.Certificate.SHA256 {
		t.Fatal("certificate digest")
	}
	var parsed struct {
		Statement json.RawMessage `json:"statement"`
		Votes     []struct {
			Signer    uint64 `json:"signer"`
			Signature []byte `json:"signature"`
		} `json:"votes"`
	}
	if err := json.Unmarshal(certificate, &parsed); err != nil {
		t.Fatal(err)
	}
	quorum, ok := byID["source-terminal-quorum"]
	if !ok || !bytes.Equal(parsed.Statement, []byte(quorum.JSON)) || len(parsed.Votes) != 1 || parsed.Votes[0].Signer != 1 {
		t.Fatal("certificate statement or vote")
	}
	key, _ := hex.DecodeString(*quorum.Key)
	message, _ := hex.DecodeString(quorum.Hex)
	if !verify([32]byte(key), message, parsed.Votes[0].Signature) {
		t.Fatal("certificate quorum signature")
	}
	if !bytes.Contains([]byte(byID["maintenance"].JSON), []byte("9007199254740993")) {
		t.Fatal("large JSON integer vector is missing")
	}
}
