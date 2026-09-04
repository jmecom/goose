# IFC experiments

The current Goose experiment follows Microsoft's FIDES tool-middleware design.
See [FIDES.md](FIDES.md) for configuration, the deterministic demo, and limits.
It uses coarse confidentiality and integrity labels, hidden variables, isolated
LLM processing, and optional tool blocking. It is disabled unless configured.

The original reader-set observer below remains available as a comparison. Its
labels and trace are separate from the FIDES experiment; neither enables the other.

## Original reader-set observer

This is observation-only Rust instrumentation. It labels individual values,
records their dependencies, and gives each provider response the intersection
of its inputs' permitted readers. It does not block reads, tools, or publication.
It does not implement Buzz's capability checks, integrity model, or releases.

Each computation includes its execution context, instructions, full supplied
history, tool schemas, model settings, and explicit control dependencies. A
context remembers what it has actually seen. A `would_deny` read that was still
delivered narrows the context; a genuinely withheld read does not. Empty reader
sets allow nobody, and missing references or unknown labels stay unknown.

## Run the deterministic experiment

From the Goose repository root:

```sh
. ./bin/activate-hermit
./bin/cargo test -p goose-ifc
./bin/cargo run -p goose-ifc --example selective > /tmp/ifc-fixture.jsonl
```

The example first computes a private investigation, then an independent shared
patch in a separate context. The patch's publication check allows Alice and Bob.
Delivering the private result into the shared context makes its subsequent
computation private, even though the read check would have denied delivery.
These are deterministic fixture computations, not model-completion measurements
or an implemented handover UI.

## Trace Goose's provider calls

Set `GOOSE_IFC_TRACE_FILE` to a new local file before starting Goose. The shared
`stream_response_from_provider` path observes the legacy loop, the state-machine
loop, and their stream-start retries. No Berd changes are needed; Berd can run
this backend through its existing `GOOSE_BIN` override.

```sh
GOOSE_IFC_TRACE_FILE=/tmp/goose-ifc-run-1.jsonl /path/to/modified/goose serve
```

The file must not already exist. On Unix it is created with mode 0600. File-open
or write failures leave agent behavior unchanged and emit a fixed diagnostic
without the path or error details. This output is separate from Goose telemetry.
The environment is read once; changing it requires restarting the process.

Records contain opaque IDs, SHA-256 digests, labels, and dependency edges, not
prompts, SQL, tool names, arguments, filenames, error text, or response bodies.
The digest covers `serde_json::to_vec` of the entire value, including metadata.
Treat even these logs as private: digests permit guessing small values, and
dependency edges and labels reveal activity. They are not a Bob-safe rendering.

Messages and tool schemas are recorded individually. Tool arguments inherit
the whole generating response's label. A tool result is observed when it is
supplied to the next provider call, with the corresponding request as a control
dependency; this is not a complete tool-execution log. No tool is reexecuted by
the observer. All chunks of a response inherit its call label; there is no
token-level attribution. Provider errors are unknown and affect later retries.

`inputs_complete` describes the arguments at the Rust `Provider::stream`
boundary, after Goose's message filtering and toolshim input conversion. It
does not describe the provider's wire encoding or count hidden provider-side
calls. Providers declaring that they manage their own context get an incomplete
manifest and unknown output labels.

## Supply fixture labels

Without a policy, sources and contexts are unknown. The observer never guesses
confidentiality from text, a tool name, a model-authored label, or an audience
annotation. For controlled experiments, `GOOSE_IFC_POLICY_FILE` can name a JSON
file supplied by the human before the process starts:

```json
{
  "domains": {
    "exact-fixture-session-id": {
      "audience": {"kind":"known","realm":"fixture","readers":{"only":["alice","bob"]}},
      "retained_context": {"kind":"known","realm":"fixture","readers":{"only":["alice","bob"]}},
      "policy_epoch": "fixture-v1"
    }
  },
  "sources": {
    "exact-value-sha256-from-fixture": {
      "kind":"known","realm":"fixture","readers":{"only":["alice"]}
    }
  }
}
```

The test fixtures demonstrate generating these digest mappings with
`content_digest`. The policy is a trusted classification assertion, not an ACL,
an endorsement, or permission to query a source. A known initial domain must
account for retained history and control state, not merely the newest user
message. Do not classify an ordinary private chat as shared because its
repository is shared. Malformed policies fall back to unknown labels.

## Current limits

The value index retains 4096 entries and the provider observer retains 64
contexts. Evicted references become unknown; an evicted context cannot regain
its configured initial label. Trace files retain the emitted records, but the
prototype does not restore contexts or provenance from them. Restarted sessions
are unknown unless the human explicitly supplies their initial classification.

This first slice does not track every transformation between model calls.
Merged messages, compacted history, toolshim postprocessing, auxiliary model
calls, and delegation still need producer references. Unclassified transformed
inputs remain unknown. The next integration should carry trusted references
through those transformations rather than classify model outputs by appearance.

Stock Goose's ordinary chat context accumulates exposure; this change does not
make it safe to erase private history or retrospectively sanitize a mixed
response. Isolated contexts exist in the deterministic experiment, not yet as a
new planner mode. No production IFC protection or general noninterference is
claimed, and existing Goose logs and tools are not restricted by this module.
