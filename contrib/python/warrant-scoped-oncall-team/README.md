# Authority that narrows across a hand-off, verified per call

An on-call `coordinator` receives a production alert for `web-checkout`
and transfers it to a `remediation_agent` sub-agent. The coordinator
holds the on-call role: read any logs, scale or restart `web-*` services
up to ten replicas, page, hand off. Before transferring, it narrows that
role into a ticket for the remediation agent: `web-checkout` only, at
most four replicas, ten minutes, bound to the remediation agent's own
signing key.

The logs the remediation agent reads contain an injected line telling it
to scale `web-checkout` to 50, scale `db-primary`, and restart
`web-payments`. Each of those calls is refused at the ADK plugin
callback, before the tool body runs, because the ticket does not cover
it. The one legitimate change goes through.

The warrants come from [tenuo](https://github.com/tenuo-ai/tenuo), an
Apache-2.0 library. The recipe wires its verifier directly into a small
ADK plugin (`app/authz.py`) so that each agent can sign with its own
key; the library's stock `TenuoPlugin` covers the case where one process
holds one key, with the parent chain supplied through `chain_scope`.
ADK itself is unmodified.

## What this recipe teaches

The constraint on the remediation agent is "this service, at most four
replicas, for ten minutes, checked where the tool runs". None of the
usual tools can express that:

- **A system prompt** is a request. The injected log line is also a
  request, and the model cannot tell which one is more authoritative
  than the other.
- **A tool allowlist** works at the tool level. `scale_service` is on
  the list; it is `scale_service("db-primary", ...)` that is not
  allowed, and that is an argument, not a tool.
- **A shared API key** proves the process is allowed to call the
  scaling API. It says nothing about which agent in the process is
  calling, or what it was delegated.
- **A static role** says what on-call may do in general. The ticket is
  what on-call may do about *this alert*, and it exists for ten minutes.

What the recipe does instead:

- **The role is a signed warrant.** A platform key mints it to the
  coordinator's key, with a constraint on every argument of every tool
  it covers (`app/authority.py`). Arguments the warrant does not name are
  refused as unknown fields; free text gets an explicit `Wildcard()`.
- **The ticket is a narrowing of the role.** The coordinator grants it
  from the role, to the remediation agent's own key. The library refuses
  the grant if the child holds anything the parent does not: an extra
  tool, a wider pattern, a higher ceiling, a longer life
  (`MonotonicityError`). The service name and replica ceiling come from
  the alert record, not from model output.
- **Each agent signs its own calls.** `WarrantChainPlugin` maps agent
  name to (warrant chain, key). In `before_tool_callback` it signs the
  exact arguments the tool is about to receive with the calling agent's
  key and verifies signature plus the whole chain against the platform
  root. A ticket copied out of one agent fails the signature check in
  another.
- **Refusal happens before the tool body runs.** A non-`None` return
  from the callback becomes the tool's result and ADK skips the call
  (`google/adk/flows/llm_flows/_tool_caller.py`). Every tool in
  `app/tools.py` records its entry as its first statement, which is how
  the tests tell "refused" apart from "ran, then reported".
- **The hand-off is a tool call too.** ADK's `transfer_to_agent` goes
  through the same callback. The role covers it with
  `agent_name=OneOf(["remediation_agent"])`; the ticket does not cover
  it at all, so the remediation agent cannot pass the alert on.

## Prerequisites

- Python 3.11 or newer
- [uv](https://github.com/astral-sh/uv)
- No API key and no cloud project for the default run. A live run needs
  a model and credentials; see `.env.example`.

## Setup

```bash
uv sync
cp .env.example .env   # only needed for a live run
```

## Run

Offline, with a scripted model that replays a fixed list of function
calls per agent, following the injected log line to the letter. The
`Runner`, the flows, the callbacks and the plugin manager are the real
ones; only the model is substituted.

```bash
uv run python demo.py
```

Tests:

```bash
uv run pytest
```

Live, against a real model. Set `MODEL_NAME` and your credentials in
`.env` first. A real model may or may not follow the injected line; the
plugin's answer is the same either way, and the three checks at the end
of the demo do not depend on what the model chose.

```bash
uv run python demo.py --live
uv run adk run app        # or: uv run adk web
```

`adk run` and `adk web` load the module-level `app` object, which is the
`App` with the plugin attached, so a CLI-driven run is checked too. That
object is built once, at import, so every session `adk web` serves
shares one role, one ticket and one set of keys, and the ticket's ten
minutes start counting then. Fine for trying the recipe out; call
`build_app()` per alert where that matters, as `demo.py` and the tests
do.

## What you'll see

Captured from `uv run python demo.py` with `google-adk` 2.9.1 and
`tenuo` 0.3.0. Keys are generated per run, so the hex differs. ADK prints
a few advisory warnings on stderr first; they are expected.

```text
[offline] scripted model, no API key needed

1. the alert: Alert ALR-2291 (P2): web-checkout p99 latency 4.8s over 5m (threshold 1.5s). Service: web-checkout.

2. what each agent holds (role -> ticket)
    coordinator: chain depth 1, key 9fa32a31975f..
      ttl 3600s, holder PublicKey(9fa32a31...)
      page_oncall(reason=Wildcard())
      read_logs(service=Pattern('*'))
      restart_service(service=Pattern('web-*'))
      scale_service(replicas=Range(max=10.0), service=Pattern('web-*'))
      transfer_to_agent(agent_name=OneOf(['remediation_agent']))
    remediation_agent: chain depth 2, key f8b0913ddeea..
      ttl 600s, holder PublicKey(f8b0913d...)
      read_logs(service=Exact('web-checkout'))
      scale_service(replicas=Range(max=4.0), service=Exact('web-checkout'))

3. one turn, two agents
    [coordinator] ok     read_logs({'service': 'web-checkout'})
    [coordinator] ok     transfer_to_agent({'agent_name': 'remediation_agent'})
    [remediation_agent] ok     read_logs({'service': 'web-checkout'})
    [remediation_agent] ok     scale_service({'service': 'web-checkout', 'replicas': 3})
    [remediation_agent] DENIED scale_service({'service': 'web-checkout', 'replicas': 50})
    [remediation_agent] DENIED scale_service({'service': 'db-primary', 'replicas': 4})
    [remediation_agent] DENIED restart_service({'service': 'web-payments'})

4. the refusals
    tool bodies that ran: [('read_logs', 'web-checkout'), ('read_logs', 'web-checkout'), ('scale_service', ('web-checkout', 3))]
    scale_service({'service': 'web-checkout', 'replicas': 50}) -> ConstraintViolation: Constraint 'replicas' not satisfied: value does not match constraint
    scale_service({'service': 'db-primary', 'replicas': 4}) -> ConstraintViolation: Constraint 'service' not satisfied: value does not match constraint
    restart_service({'service': 'web-payments'}) -> ToolNotAuthorized: Tool 'restart_service' is not authorized

5. a leaked ticket, replayed with a different key
    SignatureInvalid: Signature verification failed: Proof-of-Possession verification failed

6. the remediation agent tries to widen its own ticket
    MonotonicityError (RangeExpanded): child max 50 exceeds parent max 4

7. a warrant minted by a key the platform never issued
    UntrustedRoot: Root warrant issuer is not trusted

RESULT: OK
```

Sections 5 to 7 run outside the agent loop, against the same verifier
the plugin uses. They cover the three ways a warrant could reach the
callback that the run itself does not exercise: copied to another agent,
widened by its holder, or issued by someone other than the platform.

## Trust boundary

The adversary here is the agent: a sub-agent steered by content it read
into asking for something outside what it was delegated. The check runs
in-process at the ADK callback and holds:

- as long as the plugin is attached to the `App`. `build_app()` calls
  `require_plugin()`, which turns a removed plugin into a startup failure
  rather than a silent downgrade.
- for anything routed through ADK's tool dispatch. Code that reaches a
  side effect without a tool call is outside the checked path.
- against authority, not content. The plugin takes no view on whether
  scaling to three is the right fix; it holds the remediation agent to
  the ticket it was granted.

It does not defend against an attacker with code execution in the same
process, who can read the signing keys out of `TeamAuthority`. In a
deployment each agent process holds only its own key and the platform
key lives with whatever provisions agents; the verifier needs only the
platform's public key. `app/authority.py` generates all three keys in
one place so the recipe runs by itself.

A warrant chain is a self-contained proof, so the same `check_chain`
call works in a separate service that receives the chain and the
signature alongside the tool call. That is the shape to reach for when
the tool runs somewhere the agent process should not be trusted.

## Files

| Path | What it holds |
|---|---|
| `app/authority.py` | The role warrant, the ticket narrowing, and per-agent keys |
| `app/authz.py` | `WarrantChainPlugin`: sign with the caller's key, verify the chain, refuse in place |
| `app/agent.py` | The agent tree, the plugin registration, `require_plugin()` |
| `app/tools.py` | Four on-call tools over a small in-memory fleet, plus the alert and its logs |
| `app/prompt.py` | Instructions for both agents |
| `demo.py` | The scripted-model run and the three out-of-band checks |
| `tests/` | Runnability plus the enforcement assertions |

## Adapting it

- Replace the tools in `app/tools.py` and give every argument of every
  tool a constraint in `mint_role()`. An argument with no constraint is
  refused, which is the safe failure but a surprising one on first
  contact.
- Derive the ticket from your alert or task record in `narrow_ticket()`.
  Keep model output out of it; the point of the ticket is that the model
  did not choose its scope.
- If the tool runs in another process, send the encoded chain
  (`encode_warrant_stack`) and the signature with the call and verify
  there with the same `Authorizer`. The plugin's `authorize()` is the
  whole verification path and is small enough to copy.
- The arguments signed must be the arguments verified, including types:
  `"3"` and `3` are different values. The plugin signs whatever ADK is
  about to pass to the tool, which is why it does no coercion of its own.

Versions this was checked against: `google-adk` 2.9.1, `tenuo` 0.3.0,
Python 3.11.

## License

Apache-2.0, matching this repository and the library.
