# SauronID Go SDK

Go client + policy enforcement layer for the SauronID core server.
Feature-parity with the TypeScript SDK in `agentic/` and the Python SDK
in `clients/python/sauronid_client/`.

## Install

```bash
go get github.com/sauronid/go-sdk
```

Requires Go 1.22+.

## Quickstart

```go
package main

import (
	"context"
	"errors"
	"log"

	"github.com/sauronid/go-sdk"
)

func main() {
	ctx := context.Background()

	cache := sauronid.NewPolicyCache(sauronid.PolicyCacheOptions{
		CoreURL:  "http://localhost:8080",
		AdminKey: "...",
	})
	defer cache.Stop()
	if _, err := cache.Load(ctx, "pol_abc"); err != nil {
		log.Fatal(err)
	}

	budget := sauronid.NewBudgetTracker(sauronid.BudgetTrackerOptions{
		PolicyID: "pol_abc",
		FlushFn: sauronid.ServerPush(sauronid.ServerPushOptions{
			CoreURL: "http://localhost:8080",
			AgentID: "agent-1", PolicyID: "pol_abc",
		}),
	})
	defer budget.Stop()

	sendEmail := sauronid.ToolFunc(func(args ...interface{}) (interface{}, error) {
		// real tool body
		return "queued", nil
	})
	guarded := sauronid.Bind("send_email", sendEmail, sauronid.BindOptions{
		AgentID: "agent-1", PolicyID: "pol_abc",
		Cache: cache, BudgetTracker: budget,
		ClassifyAction: func(_ string, args []interface{}) map[string]interface{} {
			return map[string]interface{}{"amount_usd": 0.10}
		},
	})

	if _, err := guarded("hello@example.com"); err != nil {
		var denied *sauronid.PolicyDeniedError
		if errors.As(err, &denied) {
			log.Printf("denied: %s — %s", denied.Check, denied.Reason)
		}
	}
}
```

For the one-shot wiring use `sauronid.CreateEnforcer(ctx, opts)`.

## API surface

- `Client` — HTTP client for agent register/revoke, policy upload/list/evaluate, spend ledger, stats submit.
- `PolicyCache` — fetches compiled policies via `GET /v1/policy/:id`, background refresh.
- `BudgetTracker` — in-memory spend + rate ledger, optional server-side flush.
- `Bind` — wraps an arbitrary tool with policy enforcement.
- `Enforcer` / `CreateEnforcer` — one-shot wiring.
- `Evaluate` — pure invariant evaluator (7 checks).
- `SignCall`, `GeneratePopKeyPair`, `SignPopChallenge` — call-signing + PoP key helpers.
- `SubmitStats` — POST a pre-computed stats proof to the core.

Full reference: `go doc github.com/sauronid/go-sdk`.

## Cross-impl parity

Verdict semantics (allow/deny strings) match the TypeScript and Python
evaluators byte-for-byte. The `cross_impl_test.go` file hard-codes
identical fixtures so a regression in any of the three SDKs surfaces
immediately.

## Known limitations

- **No ZK proof generation.** snarkjs is JavaScript-only. Compute proofs
  via the TS or Python SDKs; Go can only submit them (`SubmitStats`).
- **No local policy YAML parser.** Upload policies via the server's
  `POST /v1/policy` endpoint (`Client.UploadPolicy`) — the server returns
  the canonical compiled AST that the cache then fetches.
- **No LangChain / OpenAI / Anthropic adapters.** Go does not yet have a
  canonical LLM-tool framework. The `Bind` primitive is framework-agnostic
  — wrap any `ToolFunc`.
- **HTTP only.** No gRPC interface in this version.

## Layout

| File | Purpose |
|---|---|
| `types.go` | Verdict, Action, Binding, CompiledPolicy types |
| `evaluator.go` | The 7-invariant pure evaluator + ComputeNowTzHhmm |
| `policy_cache.go` | HTTP-backed compiled-policy cache |
| `budget_tracker.go` | Spend + rate ledger, ServerPush flush |
| `bind.go` | Tool wrapper, PolicyDeniedError, PolicyNotLoadedError |
| `enforcer.go` | CreateEnforcer one-shot wiring |
| `stats.go` | StatsSubmission + Client.SubmitStats |
| `pop_keys.go` | Ed25519 PoP keypair helpers |
| `call_sig.go` | Signed-call header bundle |
| `client.go` | Bare HTTP client (agent / policy / spend) |
| `examples/main.go` | End-to-end demo |
