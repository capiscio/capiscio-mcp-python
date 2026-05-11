# Policy Enforcement Wiring Plan

## Problem Statement

`@guard` only enforces the code-level `min_trust_level` from the decorator. Org/group/agent-level policies set in the dashboard are never evaluated at runtime. The full policy pipeline (bundle building, pulling, local OPA evaluation) exists but is never connected.

## Root Cause

Two disconnected initialization paths:

1. **Go core startup** (`internal/rpc/mcp_service.go`): `NewMCPService()` → `NewMCPServiceWithConfig()` → `mcp.NewService(deps)` → `NewGuard(verifier, store)` — **never passes `WithPDPClient()`**
2. **Bundle pull infrastructure** (`pkg/pdp/`): `NewLocalPDPFromEnv()` creates BundleClient → BundleManager (30s poll) → OPALocalClient (sub-ms eval) — **never called from the startup path**

The `WithPDPClient()` option exists and is tested, but only wired in test files.

## Architecture (What Already Exists)

```
capiscio-server                              capiscio-core (Go sidecar)
┌──────────────────────────┐                 ┌────────────────────────────────┐
│ PolicyResolver           │                 │ pkg/pdp/bundle_client.go       │
│   org → group → agent   │  GET /v1/bundles│   Fetch() with API key auth    │
│   merged per-agent DID   │  /{org_id}     │         ↓                      │
│         ↓                │ ◄──────────────│ pkg/pdp/bundle_manager.go      │
│ BundleBuilder (30s)      │                 │   30s poll, revision skip,     │
│   assembles OPA bundle   │                 │   backoff, staleness detect    │
│         ↓                │                 │         ↓                      │
│ GET /v1/bundles/{org_id} │                 │ pkg/pdp/opa_client.go          │
│   serves bundle JSON     │                 │   embedded OPA, sub-ms eval    │
│   (RegistryKeyAuth)      │                 │         ↓                      │
└──────────────────────────┘                 │ pkg/mcp/guard.go               │
                                             │   EvaluateToolAccess()          │
                                             │   if pdpClient != nil → PDP    │
                                             │   else → inline trust check    │
                                             └────────────────────────────────┘
```

## Policy Distribution Model

**Pull-based polling (30s).** No push/notification channel exists today.

| State | Behavior |
|-------|----------|
| Startup (server reachable) | Synchronous initial fetch. Bundle loaded. PDP active. |
| Startup (server unreachable, EM-OBSERVE/EM-GUARD) | Starts without bundle. Inline trust-level only. Background poll retries with backoff. |
| Startup (server unreachable, EM-STRICT) | Refuses to start. Fatal error. |
| Running (server goes offline) | Cached bundle continues evaluating (sub-ms). After 10m → "stale" warning. EM-STRICT → synthetic DENY. |
| Recovery (server comes back) | Next poll succeeds. Bundle hot-swaps. Backoff resets to 30s. Automatic. |

Backoff: 1s → 2s → 4s → ... → 5m max, ±25% jitter.

Future improvement: SSE/WebSocket notification to trigger `BundleManager.RefreshNow()` and reduce 30s propagation window.

---

## Fix: Two Repos

### Change 1: capiscio-core — Wire `NewLocalPDPFromEnv()` into Guard startup

#### File: `pkg/mcp/service.go`

**Current code (L14-L26):**
```go
type Dependencies struct {
	BadgeVerifier *badge.Verifier
	EvidenceStore EvidenceStore
}

func NewService(deps *Dependencies) *Service {
	if deps == nil {
		deps = &Dependencies{}
	}
	return &Service{
		guard:          NewGuard(deps.BadgeVerifier, deps.EvidenceStore),
		serverVerifier: NewServerIdentityVerifier(deps.BadgeVerifier),
	}
}
```

**New code:**
```go
import "github.com/capiscio/capiscio-core/v2/pkg/pip"

type Dependencies struct {
	BadgeVerifier *badge.Verifier
	EvidenceStore EvidenceStore
	PDPClient     pip.PDPClient // nil = badge-only mode (no org policy)
}

func NewService(deps *Dependencies) *Service {
	if deps == nil {
		deps = &Dependencies{}
	}

	var guardOpts []GuardOption
	if deps.PDPClient != nil {
		guardOpts = append(guardOpts, WithPDPClient(deps.PDPClient))
	}

	return &Service{
		guard:          NewGuard(deps.BadgeVerifier, deps.EvidenceStore, guardOpts...),
		serverVerifier: NewServerIdentityVerifier(deps.BadgeVerifier),
	}
}
```

#### File: `internal/rpc/mcp_service.go`

**Current `NewMCPServiceWithConfig` (L68-L128) — add after evidence store setup, before return:**

```go
import "github.com/capiscio/capiscio-core/v2/pkg/pdp"

// Inside NewMCPServiceWithConfig, after evidence store initialization:

// Initialize local PDP (policy enforcement) from environment.
// If CAPISCIO_BUNDLE_URL is unset, returns nil — badge-only mode.
localPDP, err := pdp.NewLocalPDPFromEnv(context.Background())
if err != nil {
    return nil, fmt.Errorf("policy enforcement init: %w", err)
}
if localPDP != nil {
    deps.PDPClient = localPDP.Manager  // BundleManager implements pip.PDPClient
}
```

**Why `localPDP.Manager` not `localPDP.Client`:** `BundleManager.Evaluate()` adds staleness detection on top of the raw OPA evaluation. `OPALocalClient.Evaluate()` is the bare evaluator without the age/mode guard.

**`NewMCPServiceWithConfig` must also accept `context.Context`** or use `context.Background()`. Since this is a startup-time call (not per-request), `context.Background()` is appropriate.

#### Env vars consumed (already implemented in `pkg/pdp/config.go`):

| Var | Required | Default | Purpose |
|-----|----------|---------|---------|
| `CAPISCIO_BUNDLE_URL` | Yes (to enable) | — | `{server_url}/v1/bundles/{org_id}` |
| `CAPISCIO_API_KEY` | Yes (when URL set) | — | Auth header for bundle fetch |
| `CAPISCIO_BUNDLE_POLL_INTERVAL` | No | `30s` | Go duration string |
| `CAPISCIO_BUNDLE_MAX_AGE` | No | `10m` | Stale threshold |
| `CAPISCIO_ENFORCEMENT_MODE` | No | `observe` | observe/guard/delegate/strict |

#### Build constraint note:

`config.go` has `//go:build opa_no_wasm`. Verify the existing build tags in CI include this. If not, this file won't compile into the binary.

---

### Change 2: capiscio-mcp-python — Set env vars + extract org_id in `connect()`

#### File: `capiscio_mcp/connect.py`

##### 2a. Make `api_key` optional (falls back to env var)

**Change signature:**
```python
@classmethod
async def connect(
    cls,
    server_id: str,
    api_key: Optional[str] = None,   # ← was required str
    *,
    server_url: str = DEFAULT_REGISTRY,
    ...
) -> "MCPServerIdentity":
```

**Add resolution at top of method body:**
```python
effective_api_key = api_key or os.environ.get("CAPISCIO_API_KEY")
if not effective_api_key:
    raise ValueError(
        "api_key argument or CAPISCIO_API_KEY environment variable is required."
    )
```

Replace all uses of `api_key` in the method body with `effective_api_key`.

##### 2b. Extract org_id from registration response

**After the `register_server_identity()` call (~L424), add:**
```python
org_id: Optional[str] = None

# Extract org_id from registration response
reg_data = reg_result.get("data") or {}
org_id = reg_data.get("orgId")
if org_id:
    # Persist for offline recovery
    org_id_file = effective_keys_dir / "org_id.txt"
    try:
        org_id_file.write_text(org_id)
    except OSError as exc:
        logger.warning("Could not persist org_id: %s", exc)
```

**Before registration (for cached case), add org_id recovery:**
```python
# Try loading cached org_id (avoids network call if keys already exist)
org_id_file = effective_keys_dir / "org_id.txt"
if org_id_file.exists():
    try:
        org_id = org_id_file.read_text().strip()
    except (OSError, UnicodeDecodeError):
        org_id = None
```

##### 2c. Set env vars BEFORE core is spawned

**After org_id is resolved (before badge issuance), add:**
```python
# Configure policy enforcement for Go core.
# Must be set BEFORE the first @guard call triggers CoreClient.get_instance()
# which spawns the Go binary (inherits parent env).
if org_id:
    os.environ["CAPISCIO_BUNDLE_URL"] = f"{server_url}/v1/bundles/{org_id}"
if not os.environ.get("CAPISCIO_API_KEY"):
    os.environ["CAPISCIO_API_KEY"] = effective_api_key
```

##### 2d. Add org_id to MCPServerIdentity dataclass

```python
@dataclass
class MCPServerIdentity:
    server_id: str
    did: str
    api_key: str
    server_url: str
    keys_dir: Path
    badge: Optional[str] = None
    private_key_pem: Optional[str] = None
    org_id: Optional[str] = None          # ← NEW
    _keeper: Any = field(default=None, repr=False)
```

And pass it in the return:
```python
return cls(
    server_id=server_id,
    did=did,
    api_key=effective_api_key,
    server_url=server_url,
    keys_dir=effective_keys_dir,
    badge=badge,
    private_key_pem=private_key_pem,
    org_id=org_id,                         # ← NEW
    _keeper=keeper,
)
```

##### 2e. Update `from_env()` — api_key fallback handled by connect() now

```python
# In from_env(), change:
api_key = os.environ.get("CAPISCIO_API_KEY")
if not api_key:
    raise ValueError(...)

# To:
api_key = os.environ.get("CAPISCIO_API_KEY")  # None is ok — connect() will read env
```

Actually since `connect()` now handles the fallback, `from_env()` can just pass `api_key=api_key` (which may be None). Remove the ValueError from `from_env()`.

---

### Change 3: capiscio-mcp-python — Revert per-request PDP approach from earlier this session

#### File: `capiscio_mcp/guard.py`

**Remove these additions from this session:**

1. The import of `from capiscio_mcp.pip import PIPConfig, PolicyClient` (line ~58)
2. The `_pip_config` global, `set_pip_config()`, `get_pip_config()` functions (~L88-115)
3. The `pip_config: Optional[PIPConfig] = None` field in `GuardConfig` (~L128)
4. The "Phase 2" block in `evaluate_tool_access()` that calls `_evaluate_org_policy()` (~L348-360)
5. The entire `_evaluate_org_policy()` async function (~L403-467)

#### File: `capiscio_mcp/connect.py`

**Remove these additions from this session:**

1. The imports: `from capiscio_mcp.guard import set_pip_config` and `from capiscio_mcp.pip import PIPConfig`
2. The `pdp_endpoint: Optional[str] = None` parameter from `connect()`
3. The "Step 7: Auto-configure PDP" block that calls `set_pip_config()`
4. The `pdp_endpoint` docstring lines
5. The `CAPISCIO_PDP_ENDPOINT` mention in `from_env()` docstring

#### File: `capiscio_mcp/__init__.py`

**Remove these additions from this session:**

1. `set_pip_config, get_pip_config` from the guard import block
2. The `from capiscio_mcp.pip import (PIPConfig, PolicyClient, PolicyResult)` block
3. `"set_pip_config", "get_pip_config", "PIPConfig", "PolicyClient", "PolicyResult"` from `__all__`

**Note:** `pip.py` itself is NOT deleted — it remains for enterprise users with external PDP endpoints. It's just no longer auto-configured or exported at top level.

---

## Timing: When Does the Go Core Spawn?

Critical detail for the implementing agent:

The Go core binary is spawned **lazily** — on the first call to `CoreClient.get_instance()`, which happens on the first `@guard` invocation (NOT during `connect()`).

This means:
- `connect()` sets `os.environ["CAPISCIO_BUNDLE_URL"]` 
- Later, user code calls a `@guard`-decorated function
- That triggers `CoreClient.get_instance()` → `ProcessSupervisor.start()` → `subprocess.exec()` (inherits env)
- Go binary starts → `NewMCPService()` → `NewLocalPDPFromEnv()` → reads `CAPISCIO_BUNDLE_URL` → starts polling

The env vars MUST be set before any `@guard` call. Since `connect()` runs before any tool is invoked, this ordering is guaranteed.

**File:** `capiscio_mcp/_core/lifecycle.py` — `ProcessSupervisor.start()` uses `asyncio.create_subprocess_exec(*cmd, ...)` with no `env=` kwarg, so the child inherits the parent's full env.

---

## Ordering Constraint for Implementers

```
1. connect() called
2.   → registration (needs network)
3.   → org_id extracted + persisted
4.   → os.environ["CAPISCIO_BUNDLE_URL"] set
5.   → os.environ["CAPISCIO_API_KEY"] set
6.   → badge issued + keeper started
7.   → MCPServerIdentity returned
... user code runs ...
8. @guard decorated function called
9.   → CoreClient.get_instance() [first time]
10.  → Go binary spawned (reads CAPISCIO_BUNDLE_URL from inherited env)
11.  → NewLocalPDPFromEnv() → BundleManager.RefreshNow() → first bundle loaded
12.  → gRPC server ready
13.  → EvaluateToolAccess RPC → Guard.evaluateWithPDP() → sub-ms OPA
```

---

## Existing Test Files (Reference)

| Test | Location | What it tests |
|------|----------|---------------|
| Guard with PDP | `capiscio-core/pkg/mcp/guard_pdp_test.go` | `WithPDPClient()` mock → ALLOW/DENY |
| Guard OPA integration | `capiscio-core/pkg/mcp/guard_opa_integration_test.go` | Real OPA bundle loaded, evaluates Rego |
| BundleManager | `capiscio-core/pkg/pdp/bundle_manager_test.go` | Poll, backoff, staleness |
| OPALocalClient | `capiscio-core/pkg/pdp/opa_client_test.go` | LoadBundle + Evaluate |
| NewLocalPDP | `capiscio-core/pkg/pdp/config_test.go` | Env var parsing, initial fetch |

---

## Testing Plan

1. **Unit (Go):** In `internal/rpc/mcp_service_test.go`, set `CAPISCIO_BUNDLE_URL` + `CAPISCIO_API_KEY` env vars, call `NewMCPServiceWithConfig()`, assert `service.guard.pdpClient != nil`

2. **Integration (Go):** Start Go core with bundle URL pointing at httptest server serving a test bundle with a deny rule. Call `EvaluateToolAccess` RPC. Assert DENY with `TOOL_POLICY_DENIED`.

3. **E2E (Python):** `MCPServerIdentity.connect()` against dev registry → change policy in dashboard → wait 35s → call guarded tool → assert `GuardError` with `POLICY_DENIED`.

---

## Error Handling

| Scenario | Behavior |
|----------|----------|
| `CAPISCIO_BUNDLE_URL` not set (no org_id) | Go core starts in badge-only mode. Inline trust-level only. No crash. |
| Bundle endpoint 401/403 | `BundleClient.Fetch()` returns error. BundleManager retries with backoff. EM-OBSERVE: allow through. |
| Registration fails (no org_id extracted) | `org_id` stays None. `CAPISCIO_BUNDLE_URL` not set. Badge-only mode (graceful degradation). |
| Go binary not available | Existing `CoreConnectionError` raised on first `@guard` call. Unrelated to this change. |
| `api_key` not provided and not in env | `ValueError` raised in `connect()`. Fail fast. |

---

## What This Does NOT Change

- `pip.py` / `PolicyClient` — remains for enterprise external PDP use cases
- `EvaluatePolicyDecision` gRPC RPC — remains for explicit PDP calls from SDK code
- Badge verification flow — unchanged
- Evidence emission — unchanged
- Event emitter — unchanged
- Existing `@guard` decorator API — unchanged (no breaking changes)
- Server bundle endpoint — unchanged (already exists and works)
