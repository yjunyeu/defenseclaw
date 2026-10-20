# OpenClaw execution-agent visibility (M3.1)

The OpenClaw tool hook captures `ctx.agentId` separately for each invocation,
including `message`, and sends it to `/api/v1/inspect/tool` as
`X-DefenseClaw-OpenClaw-Agent-Id`. `X-DefenseClaw-Agent-Id` continues to carry
DefenseClaw's logical plugin identity. No identity is inferred from session keys.

The protected Gateway tool handler accepts this metadata only when its resolved
connector is `openclaw`. A connector authenticated by a scoped token takes
precedence; otherwise the existing server-configured connector applies. A
client/connector header by itself does not establish this scope.

Both ends accept canonical IDs matching `[a-z0-9][a-z0-9_-]{0,63}`. Missing,
malformed, oversized or duplicate values are omitted; they are never truncated,
repaired or replaced with the plugin ID. Inspection behavior is unchanged.
The Gateway exposes the value through `OpenClawAgentIDFromContext` and persists
it in the existing final `inspect-tool-*` audit event's `structured_json` column:

```json
{
  "action": "inspect-tool-allow",
  "target": "exec",
  "agent_id": "shared-plugin",
  "session_id": "synthetic-medical-session",
  "run_id": "existing-defenseclaw-run",
  "structured": {
    "openclaw_agent_id": "medical"
  }
}
```

This is a synthetic excerpt, not a new event schema. Existing logical identity,
session/run correlation, details and outcome remain in their existing fields.
Missing metadata is represented by an absent `openclaw_agent_id`, including on
older events. Existing collection/redaction settings still govern persistence
and export. This milestone attributes the final tool-inspection decision event;
it does not add a new identity field to every scanner finding or trace schema.
It adds no tool arguments, message content or records to identity metadata.

## Trust limitations

OpenClaw supplies the execution agent to its trusted host plugin. The Gateway
authenticates token/connector access, but does not independently authenticate
the named agent. A credential holder can report another syntactically valid
name. Unknown but valid names are recorded as reported metadata, not rejected
as unauthorized agents.

This field must not select policies, grant privileges or establish session
ownership. Before per-agent enforcement, add an authenticated binding between
the reported execution identity and its permitted agent scope. No policy rules,
thresholds, authorization privileges, LLM-request identity propagation or
database migrations are part of this milestone.

## Automated verification

From the repository root:

```bash
go test ./internal/gateway ./internal/audit -count=1
go test -race ./internal/gateway -run '^TestOpenClawToolIdentity' -count=1
```

From `extensions/defenseclaw`:

```bash
npm test -- --silent
task_build_dir=$(mktemp -d /tmp/defenseclaw-m31-build.XXXXXX)
npm run build -- --outDir "$task_build_dir"
```

The temporary build output avoids overwriting local edits to tracked `dist`
files. It does not update an installed extension or Gateway. Deploy both updated
components through the installation's normal development workflow before the
manual check. Review any existing generated-file edits before rebuilding or
installing in place.

## Manual check with synthetic agents

Use a development Gateway with the updated DefenseClaw extension enabled and
the updated DefenseClaw Gateway running with the `openclaw` connector. Keep its
existing policies, guardrails, credentials and collection settings. Ensure
`medical` and `work` are synthetic agents with the sandbox `exec` tool enabled:

```bash
openclaw agents list
```

If these names do not exist, create them in that development installation:

```bash
openclaw agents add medical --workspace /tmp/m31-medical-workspace --non-interactive
openclaw agents add work --workspace /tmp/m31-work-workspace --non-interactive
```

Run both turns through the same active Gateway; do not use `--local`, which
requires exclusive state-directory ownership:

```bash
openclaw agent --agent medical --message "Use the exec tool once to run exactly: printf synthetic-m31-medical. Then reply done." --json &
medical_pid=$!
openclaw agent --agent work --message "Use the exec tool once to run exactly: printf synthetic-m31-work. Then reply done." --json &
work_pid=$!
wait "$medical_pid"
wait "$work_pid"
```

Set the path below to the installation's configured local audit database
(normally `~/.defenseclaw/audit.db`) and inspect the most recent decisions:

```bash
sqlite3 -readonly "$HOME/.defenseclaw/audit.db" '
SELECT timestamp, action, target AS tool, agent_id AS defenseclaw_agent_id,
       json_extract(structured_json, "$.openclaw_agent_id") AS openclaw_agent_id,
       session_id, run_id, request_id
FROM audit_events
WHERE action LIKE "inspect-tool-%"
ORDER BY timestamp DESC
LIMIT 20;'
```

Verify that both execution-agent names appear with the same logical plugin ID,
their own sessions, and the existing inspection outcomes. A model can decline
to call a tool; confirm an actual tool invocation occurred before interpreting
an absent event. The deterministic automated hook and Gateway tests also cover
the `message` branch without sending a message to a real recipient.
