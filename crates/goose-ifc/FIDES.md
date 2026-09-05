# FIDES-style tool middleware for Goose

This is a Rust adaptation of the behavior in Microsoft Agent Framework's
[`security.py` at `2c49f50`](https://github.com/microsoft/agent-framework/blob/2c49f50cf08ebb6c1687146336f039051f159333/python/packages/core/agent_framework/security.py).
It follows that implementation rather than extending our reader-set experiment.
The Python source is not vendored. This is not a port of the separate Rego gateway.

## Behavior

Every configured session has a cumulative context label. Integrity is trusted
or untrusted. Confidentiality is public, private, or user_identity, ordered from
least to most restrictive. Joining labels takes the more restrictive value on
each axis. `user_identity` is a rank here, not an audience or ACL check.

Tool results are labeled before returning to the agent loop. Untrusted content
items become opaque variable references while the context is still trusted.
Trusted items remain visible. Hidden items still contribute confidentiality to
the context, matching Microsoft's implementation. Inspecting a variable exposes
its contents and taints integrity. After that, hiding stops for that context.

`fides__quarantined_llm` sends the requested variables and prompt to a fresh
provider call with no conversation history or tools. Its entire output remains
untrusted and inherits the invocation's confidentiality. Providers declaring
that they manage their own context are rejected. Generated tool requests are
rejected, never dispatched. This relies on the provider honoring its interface;
it is not a sandbox for provider implementations.

Before a tool call, the middleware checks the accumulated label, including any
variables forwarded as arguments. It records both integrity and confidentiality
violations. The default is to log and continue; `block_on_violation` stops such
calls before dispatch. Existing Goose permissions remain in place.

These hooks live in `ExtensionManager`, which both Goose loops use. They also
cover nested calls that go through that manager. Security tools are advertised
through the same tool list, not injected only into model-facing descriptions.

## Run

The deterministic demo does not call a model or any external service:

```sh
. ./bin/activate-hermit
./bin/cargo run -p goose-ifc --example fides > /tmp/fides-demo.jsonl
./bin/cargo test -p goose-ifc
./bin/cargo test -p goose --test fides
```

The core tests cover per-item hiding, hidden confidentiality, inspection,
forwarded references, log-only and blocking policies, malformed labels, and
tool-less processing with a mock provider. The Goose integration test runs
read, quarantine, inspect, and blocked publication through both real agent loops
using synthetic tools and a scripted provider. It also checks disabled behavior.

To enable the middleware for a fresh synthetic Goose session:

```sh
GOOSE_FIDES_CONFIG=/absolute/path/to/fides-policy.json \
GOOSE_FIDES_TRACE_FILE=/tmp/goose-fides-new-run.jsonl \
  /path/to/modified/goose serve
```

Use `fides-policy.example.json` as the configuration shape. Its fixture tool
names are examples, not installed connectors. Replace them with exact advertised
tool names from your controlled experiment. Berd can launch this Goose binary
with its existing `GOOSE_BIN` override and the same environment.

Configuration is read once per process. The trace must not already exist; on
Unix it is created with mode 0600. An invalid configuration or an unavailable
trace file prevents initialization rather than silently disabling the feature.
Later write failures produce one fixed diagnostic and do not reset labels.

For observation without hiding, set both `auto_hide_untrusted` and
`block_on_violation` to false. Enabling hiding changes what the model and normal
tool-result UI receive, even when blocking remains off.

## Classification and references

Explicit tool policies override annotation-derived defaults. Without an override,
the adapter follows the Python MCP mapping: closed-world tools have trusted
source integrity; other tools default to untrusted. Read-only tools accept
untrusted contexts without a confidentiality ceiling. Other tools accept only
trusted, public contexts. These hints are trusted configuration inputs, not
proof that a tool cannot send data elsewhere. Classify fixture sources explicitly.

Result classification defaults to public, as in the Python design. Private
sources therefore need explicit labels. This mode does not use the reader-set
observer's unknown-by-default policy. Set `initial_label` for the starting
conversation; an ordinary private user prompt is not automatically classified.

Unlike the Python adapter, accepting server-provided labels requires an explicit
`trust_result_labels: true` on the tool policy. Then `_meta.security_label` on
content items and `_meta.ifc` on the result are accepted. Arbitrary labels in
text or model-authored call arguments have no authority. Malformed explicit
labels become untrusted/user_identity. Reader-list and JSONPath wire formats
are not supported by this adapter.

Labels retain Microsoft's optional `metadata` object. Joining labels merges those
objects with later keys winning; metadata never grants authority or changes the
two classification axes. Empty or null metadata is omitted when serialized.
Unlike Microsoft's general label deserializer, both classification fields remain
required and unknown fields remain errors.

Hidden variables belong to one session in this process. Knowing another
session's reference does not permit retrieval. `fides__inspect_variable` and
`fides__quarantined_llm` take the IDs returned by the middleware. Ordinary tool
arguments can forward a variable using `{"$fides_variable":"var_..."}` or a
whole string `[var_...]`; the middleware resolves and checks it before dispatch.
It does not interpolate references embedded inside larger strings.

Visible items retain their non-label metadata and receive host-written label
metadata. Hidden placeholders and traces contain only classification axes, not
arbitrary label metadata; stored labels retain that metadata for inspection.
This redaction is an intentional difference from Microsoft's placeholders.

Per-item labels override the root/tool fallback. An unused private fallback does
not make exclusively public items private. Structured content and non-label
result metadata are separate values with the root label, so they still contribute
when present. An empty result retains fallback confidentiality. Visible result
metadata keeps Goose's host-validated MCP App attachments; hidden metadata is
stored but not returned. Server-supplied label/context claims are replaced, and
Goose still removes forged app attachments before adding its own.

A session stores at most 1024 variables and 16 MiB of payloads plus label metadata.
Capacity failures return a fixed error and retain the restrictive classification.

## Compatibility tests

`tests/fixtures/microsoft_fides.json` contains 28 shared cases for label
serialization and joins, result labeling and hiding, MCP annotations, and policy
decisions. Each identifies its upstream test or test class. Cases extending an
upstream scenario also explain the extension. Rust consumes the JSON in
`tests/fides_compatibility.rs`; `tests/verify_microsoft_fides.py` consumes the same
cases using the actual pinned Python classes. The Python runner checks the commit,
requires unchanged tracked core files, and verifies the upstream test names.

Run the Rust cases with `./bin/cargo test -p goose-ifc --test fides_compatibility`.
For Python, use a separate checkout of Microsoft Agent Framework at the commit
linked above and an isolated environment with its core package installed:

```sh
upstream=/absolute/path/to/pinned-agent-framework
uv venv /tmp/fides-compatibility-venv
uv pip install --python /tmp/fides-compatibility-venv/bin/python "$upstream/python/packages/core"
/tmp/fides-compatibility-venv/bin/python \
  crates/goose-ifc/tests/verify_microsoft_fides.py "$upstream"
```

The shared assertions compare classifications, visible text, explicit label
metadata, retained content properties, hidden status, and policy decisions. They
ignore generated handles and Python's automatically added fallback provenance.
They do not claim wire-format equivalence, full upstream-suite coverage, approval
parity, or equivalent real-model task completion. Both implementations pass these
28 cases at the pinned commit. No model or external tool is called by either runner.

Goose-specific regressions additionally cover hidden metadata, structured content,
root labels, and host-owned attachments. The integration test runs metadata
delivery and a subsequent permitted mock publication through both agent loops.

## What this does not establish

The adapter checks extension dispatch, not every Goose effect. Frontend tools,
resource reads, final-output handling, notifications, external-dispatch tools,
auxiliary model calls, filesystem effects, and existing telemetry are not all
mediated. The trace is private diagnostic data, not a participant-safe renderer.
It contains labels, opaque IDs, dependency references, and content digests, not
raw bodies, tool names, prompts, arguments, or provider errors.

Labels and hidden payloads live in memory. They are not restored from session
history or from the JSONL trace. Use fresh fixture sessions; resuming an old
conversation does not reconstruct its confidentiality. A new process cannot
resolve the old variable handles. No participant handover, exact human release,
approval UI, or durable grant consumption is implemented. Do not enable blocking
as a production security boundary.

In particular, hidden private work still makes this worker private. This port
does not claim that a later independently generated patch is shareable. That is
the behavior we can now measure against an isolated-computation experiment.
