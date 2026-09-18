# Grant the ticket at hand-off; verify it at the fleet

An on-call `coordinator` holds a standing role: read logs, scale or
restart `web-*` between one and ten replicas, page, hand off. A
production alert arrives for `web-checkout`. The coordinator confirms
the symptom and calls `transfer_to_agent`. **That call is when the
ticket is minted** — from the alert record, to the `remediation_agent`'s
own signing key, for that service, at most four replicas, for ten
minutes.

The remediation agent then reads logs that contain an injected line
telling it to scale `web-checkout` to 50, scale `db-primary`, and
restart `web-payments`. Each of those calls reaches a `FleetGateway`
that holds only the platform public key. The gateway verifies the
warrant chain and the holder's proof-of-possession against the
arguments it actually received, then refuses. The one in-ticket scale
to three replicas goes through. The other services stay as they were.

The warrants come from [tenuo](https://github.com/tenuo-ai/tenuo). ADK
is unmodified. The library's stock `TenuoPlugin` covers one signing key
per process; this recipe gives each agent its own key and treats the
tool as the enforcement point, so it wires `Authorizer.check_chain`
directly.

## The pattern

Two sides, the way a production split looks even when both objects
share one interpreter:

| Side | Object | Holds | Does |
|---|---|---|---|
| Holder | `InvocationPlugin` | per-agent signing keys, the role | signs the exact tool arguments; grants the ticket at `transfer_to_agent` from the alert |
| Resource | `FleetGateway` | platform public key, the fleet | `check_chain(chain, tool, args, signature)` then mutates |

The gateway constructor takes trusted roots and nothing else. It never
sees a signing key. If the plugin is left off, the tools still run;
they present no proof and the gateway refuses. That is fail-closed
without a startup tripwire.

The ticket is not created in `build_app()`. Provision mints the
standing role and discards the platform private key. The remediation
agent has no chain until the coordinator's transfer is authorized and
`issue_ticket(alert["service"], session)` runs. The model supplies the
destination agent name. It does not supply the service the ticket
names.

## What the usual controls miss

The constraint is "this service, between one and four replicas, for ten
minutes, checked where the fleet changes":

- A system prompt is a request. The injected log line is also a
  request.
- A tool allowlist is about `scale_service`, not
  `scale_service("db-primary", 4)`.
- A shared API key proves the process may call the scaler. It does not
  say which agent is calling or what it was delegated.
- A static role is what on-call may do in general. The ticket is what
  on-call may do about *this* alert.

## Setup

```bash
uv sync
cp .env.example .env   # only needed for a live run
```

Python 3.11+, [uv](https://github.com/astral-sh/uv). The default run
needs no API key and no cloud project.

## Run

```bash
uv run python demo.py
uv run pytest
```

The offline demo substitutes only the model. A `BaseLlm` subclass
replays a fixed list of function calls per agent; the `Runner`, the
flows, the callbacks and the plugin manager are the real ones.

Live, after setting `MODEL_NAME` and credentials in `.env`:

```bash
uv run python demo.py --live
uv run adk run app        # or: uv run adk web
```

`adk run` / `adk web` load the module-level `app`, so the plugin and
gateway are on the path. That object is built once at first access:
the standing role is shared, tickets are still granted per session at
hand-off. Call `build_app()` per alert where you want a fresh role
clock.

## What you'll see

Captured from `uv run python demo.py` with `google-adk` 2.9.1 and
`tenuo` 0.3.0. Keys are generated per run. ADK prints a few advisory
warnings on stderr first; they are expected.

```text
[offline] scripted model, no API key needed

1. alert record (ticket will be granted from this, not the model)
    Alert ALR-2291 (P2): web-checkout p99 latency 4.8s over 5m (threshold 1.5s). Service: web-checkout.

2. standing role (no ticket yet)
    coordinator role: key 1bbad0211eb8..
      ttl 3600s, holder PublicKey(1bbad021...)
      page_oncall(reason=Wildcard())
      read_logs(service=Pattern('*'))
      restart_service(service=Pattern('web-*'))
      scale_service(replicas=Range(min=1.0, max=10.0), service=Pattern('web-*'))
      transfer_to_agent(agent_name=OneOf(['remediation_agent']))
    remediation_agent: no ticket (granted at transfer_to_agent, from the alert record)

3. ticket granted at hand-off
    remediation ticket: key 5d1098c3782a..
      ttl 600s, holder PublicKey(5d1098c3...)
      read_logs(service=Exact('web-checkout'))
      scale_service(replicas=Range(min=1.0, max=4.0), service=Exact('web-checkout'))

4. hand-off record
    [coordinator] ok     transfer_to_agent({'agent_name': 'remediation_agent'})

5. fleet gateway decisions
    [coordinator] ok     read_logs({'service': 'web-checkout'})
    [remediation_agent] ok     read_logs({'service': 'web-checkout'})
    [remediation_agent] ok     scale_service({'service': 'web-checkout', 'replicas': 3})
    [remediation_agent] DENIED scale_service({'service': 'web-checkout', 'replicas': 50}) [ConstraintViolation]
    [remediation_agent] DENIED scale_service({'service': 'db-primary', 'replicas': 4}) [ConstraintViolation]
    [remediation_agent] DENIED restart_service({'service': 'web-payments'}) [ToolNotAuthorized]
    fleet after: {'web-checkout': 3, 'web-payments': 3, 'web-catalog': 2, 'db-primary': 1}

6. denials the model saw
    scale_service({'service': 'web-checkout', 'replicas': 50}) -> ConstraintViolation: Constraint 'replicas' not satisfied: value does not match constraint
    scale_service({'service': 'db-primary', 'replicas': 4}) -> ConstraintViolation: Constraint 'service' not satisfied: value does not match constraint
    restart_service({'service': 'web-payments'}) -> ToolNotAuthorized: Tool 'restart_service' is not authorized

7. leaked ticket, replayed with a different key
    SignatureInvalid: Signature verification failed: Proof-of-Possession verification failed

8. remediation agent tries to widen its own ticket
    MonotonicityError (RangeExpanded): child max 50 exceeds parent max 4

9. a warrant minted by a key the platform never issued
    UntrustedRoot: Root warrant issuer is not trusted

RESULT: OK
```

Sections 7 to 9 run against the same `Authorizer` the gateway uses. They
cover a copied chain, a widened grant, and an issuer the platform
never trusted.

A live model may or may not follow the injected line. The gateway's
answer is the same either way. Replica values must be the type the
warrant signed: `"3"` and `3` are different, and this plugin does not
coerce them.

## Trust boundary

The adversary is the agent: a sub-agent steered by content it read
into asking for something outside the ticket. The check holds:

- at the gateway, for every fleet mutation. The plugin is how the
  holder signs; it is not how the fleet changes.
- once per call. The plugin registers each proof under ADK's
  `function_call_id` and the tool body takes it exactly once, so a
  proof is never written to session state and cannot be presented
  again by a later call. A gateway in its own process should add
  replay protection of its own; the library ships a nonce store for
  that.
- for `transfer_to_agent`, which is an ADK framework tool, so the
  plugin both authorizes the transfer and grants the ticket.
- against authority, not content. Scaling to three is in-ticket. The
  gateway does not judge whether three was the right fix.

It does not defend against an attacker with code execution in the same
process, who can read the holder keys out of `OnCallAuthority`. In a
deployment each agent process holds only its own key, the platform key
stays with whatever provisions agents, and the gateway process is
given the public root. `provision()` generates all three keys in one
place so the recipe runs by itself, then drops the platform private
key.

A warrant chain is a self-contained proof. `encode_warrant_stack` is
the artifact you send with the call when the gateway lives in another
process; `FleetGateway.invoke` is the verification path you run there.

## Files

| Path | What it holds |
|---|---|
| `app/authority.py` | Standing role, per-agent keys, `issue_ticket` at hand-off |
| `app/plugin.py` | Sign invocations; grant the ticket on `transfer_to_agent` |
| `app/gateway.py` | `Authorizer` + fleet; the only mutation path |
| `app/tools.py` | Thin wrappers that present the proof to the gateway |
| `app/alert.py` | The trusted alert record the ticket is granted from |
| `app/agent.py` | The agent tree and `build_app()` |
| `demo.py` | Scripted-model run and the three out-of-band checks |

## Adapting it

- Replace the fleet methods in `FleetGateway._execute`. Give every
  argument of every tool a constraint in `mint_role()` and
  `grant_ticket()`. An argument with no constraint is an unknown-field
  refusal.
- Keep `grant_ticket` / `issue_ticket` on the hand-off path, reading
  the task record (alert, ticket, order). Do not take the service
  name from model output.
- Move `FleetGateway` to the process that owns the side effect. Send
  `encode_warrant_stack(chain)` and the signature with the call;
  construct the gateway with the platform public key.
- Replica floors belong in the warrant (`Range(1, 4)`), not only in
  the tool body's input validation. A missing min is a ticket that
  permits scale-to-zero.

Versions this was checked against: `google-adk` 2.9.1, `tenuo` 0.3.0,
Python 3.11.

## License

Apache-2.0, matching this repository and the library.
