package sauronid

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// CallSigHeaders is the five-header bundle that authenticates a single
// outbound SauronID-protected request.
type CallSigHeaders struct {
	AgentID            string
	CallTS             string
	CallNonce          string
	CallSig            string
	AgentConfigDigest  string
}

// SetOn copies every header onto h. Keys use the canonical x-sauron-* form.
func (s CallSigHeaders) SetOn(h interface{ Set(string, string) }) {
	h.Set("x-sauron-agent-id", s.AgentID)
	h.Set("x-sauron-call-ts", s.CallTS)
	h.Set("x-sauron-call-nonce", s.CallNonce)
	h.Set("x-sauron-call-sig", s.CallSig)
	h.Set("x-sauron-agent-config-digest", s.AgentConfigDigest)
}

// SignCallParams configures SignCall.
type SignCallParams struct {
	AgentID           string
	AgentConfigDigest string
	PrivateKey        ed25519.PrivateKey
	Method            string
	Path              string
	Body              []byte
}

// SignCall computes the canonical SauronID call signature.
//
// Payload format mirrors the Python SDK byte-for-byte:
//
//	METHOD|PATH|sha256_hex(BODY)|TS_MS|NONCE_HEX
//
// Returns the five headers the server expects.
func SignCall(p SignCallParams) (CallSigHeaders, error) {
	if len(p.PrivateKey) != ed25519.PrivateKeySize {
		return CallSigHeaders{}, fmt.Errorf("private key wrong size: got %d want %d", len(p.PrivateKey), ed25519.PrivateKeySize)
	}
	ts := time.Now().UnixMilli()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return CallSigHeaders{}, fmt.Errorf("sign call: read nonce: %w", err)
	}
	nonceHex := hex.EncodeToString(nonce[:])
	bodyHash := sha256.Sum256(p.Body)
	payload := fmt.Sprintf("%s|%s|%s|%d|%s",
		strings.ToUpper(p.Method),
		p.Path,
		hex.EncodeToString(bodyHash[:]),
		ts,
		nonceHex,
	)
	sig := ed25519.Sign(p.PrivateKey, []byte(payload))
	return CallSigHeaders{
		AgentID:           p.AgentID,
		CallTS:            fmt.Sprintf("%d", ts),
		CallNonce:         nonceHex,
		CallSig:           base64.RawURLEncoding.EncodeToString(sig),
		AgentConfigDigest: p.AgentConfigDigest,
	}, nil
}
