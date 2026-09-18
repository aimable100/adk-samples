# Grant the ticket at hand-off, verify it at the fleet

An on-call agent team handles a production alert. The coordinator
triages, then hands the alert to a remediation sub-agent. Somewhere in
the logs the sub-agent reads is a line that looks like an instruction:
scale this service to 50, scale the database, restart payments. This
recipe shows how to make sure the sub-agent can act on the alert it was
given and nothing else, no matter what it reads, and how to prove
afterwards what it did.

The mechanism is a **warrant**: a signed grant that says which tools may
be called, with which argument values, by which key, until when. The
coordinator holds a standing one for the on-call role. When it hands
the alert off, it narrows that role into a ticket for the sub-agent:
this service, one to four replicas, ten minutes, bound to the
sub-agent's own key. Every tool call then goes to a gateway that holds
nothing but the platform's public key. The gateway checks the chain
and the signature against the arguments it actually received, runs the
tool if they fit, and signs a receipt either way.

The warrants come from [tenuo](https://github.com/tenuo-ai/tenuo), an
Apache-2.0 library. ADK itself is unmodified.

## Why not a prompt, an allowlist, or a role

The requirement is small and specific: *this service, between one and
four replicas, for the next ten minutes, checked where the fleet
changes.* The usual controls cannot say it.

A system prompt is a request to the model. The injected log line is
also a request to the model, and nothing about the second one marks it
as less authoritative than the first. A tool allowlist works at the
level of tool names: `scale_service` is allowed, but the problem is
`scale_service("db-primary", 4)`, and that is an argument. A shared API
key on the scaling service proves the process may call it; it says
nothing about which agent inside the process is calling, or what that
agent was delegated. A static role describes what on-call may do in
general, but what matters here is what on-call may do about *this*
alert, and that should stop existing when the alert is resolved.

A warrant covers all four at once because the constraint lives in a
signed object that travels with the task, can only get narrower as it
is passed along, and is verified by the thing that performs the action.

## How the recipe does it

Read `app/` in this order and the story follows the order of events.

**Provisioning** (`app/authority.py`). A platform key mints the
standing role to the coordinator's key: read any logs; scale or
restart `web-*` services between one and ten replicas; page the
secondary on-call; hand off to the remediation agent. Scaling to five
or more replicas is marked as an approval gate, which is explained
below. After minting, the platform's private key is discarded. The
only thing that survives is its public key, which is what the gateway
trusts.

**The alert** (`app/alert.py`). A record from the alerting system, with
the service name in it. This is the trusted input. The model will read
and talk about the alert, but the ticket is built from this record,
never from anything the model says.

**Hand-off** (`app/plugin.py`). The coordinator reads the logs and
decides to transfer. In ADK a transfer is a tool call,
`transfer_to_agent`, so it passes through the same plugin callback as
every other tool. The plugin checks that the coordinator's role permits
that transfer, and only then grants the ticket: the role narrowed to
the alert's service, one to four replicas, ten minutes, bound to the
remediation agent's own key. The library refuses the grant if the
ticket would hold anything the role does not. Before this moment the
remediation agent has no authority at all.

**Signed calls** (`app/plugin.py`, `app/tools.py`). For every fleet
tool call, the plugin signs the exact arguments ADK is about to pass
with the calling agent's key and registers that proof under ADK's
per-call id. The tool body takes the proof once and presents it, with
the warrant chain, to the gateway. Nothing about a proof is written to
session state, so a proof cannot be reused by a later call.

**Verification** (`app/gateway.py`). `FleetGateway` is constructed
with the platform's public key and nothing else. Its `invoke` method is
the only code that changes replica counts. It verifies that the chain
leads back to the platform, that no link widened its parent, that
nothing has expired, that the leaf permits this tool with these exact
argument values, and that the signature was made by the leaf's holder.
Then it runs the tool. On any failure it returns a refusal, which ADK
hands back to the model as the tool's result, and the fleet is
untouched. If the plugin is left off entirely, the tools still run,
present no proof, and are refused. Nothing needs to check at startup
that the guard is attached.

**Receipts** (`app/gateway.py`). The gateway signs a receipt for every
decision, allowed or refused, with a key of its own. Anyone with the
gateway's public key can verify a receipt later, with no gateway, no
agent and no network involved. Tickets also carry a delegation receipt
that names the parent they were narrowed from.

**Approval above the ticket.** The role permits up to ten replicas,
but five or more is an approval gate on the warrant: the call needs a
signed approval from the SRE lead's key as well as the holder's. The
ticket stays at one to four, so the remediation agent never meets the
gate; anything it asks for above four is refused by the ticket rather
than held for approval. The gate is part of the warrant and is
inherited by every ticket granted from the role.

Put together, the two sides look like this even though both live in one
interpreter here:

| Side | Object | Holds | Does |
|---|---|---|---|
| Holder | `InvocationPlugin` | the role, one signing key per agent | grants the ticket at hand-off; signs each call's exact arguments |
| Resource | `FleetGateway` | the platform's public key, its own receipt key, the fleet | verifies chain and signature, runs the tool, signs a receipt |

One note on why the recipe wires the verifier itself. The library's
stock `TenuoPlugin` for ADK assumes one signing key per process. This
recipe gives each agent its own key and treats the tool as the
enforcement point, so it calls `Authorizer.check_chain` directly from a
plugin of about a hundred lines.

## Setup

Python 3.11 or newer and [uv](https://github.com/astral-sh/uv). The
default run needs no API key and no cloud project.

```bash
uv sync
cp .env.example .env   # only needed for a live run
```

## Run

```bash
uv run python demo.py
uv run pytest
```

The offline demo replaces only the model: a `BaseLlm` subclass replays
a fixed list of function calls per agent, following the injected log
line to the letter. The ADK `Runner`, its flows, its callbacks and its
plugin manager are the real ones.

For a live run, set `MODEL_NAME` and your credentials in `.env`:

```bash
uv run python demo.py --live
uv run adk run app        # or: uv run adk web
```

A real model may or may not follow the injected line. The gateway's
answer is the same either way, and the checks at the end of the demo
do not depend on what the model chose. `adk run` and `adk web` load
the module-level `app`, which is built once on first access: the
standing role is shared across sessions, while tickets are still
granted per session at hand-off. Call `build_app()` per alert if you
want a fresh role clock.

## What you'll see

Captured from `uv run python demo.py` with `google-adk` 2.9.1 and
`tenuo` 0.3.0. Keys are generated per run, so the hex values differ.
ADK prints a few advisory warnings on stderr first; they are expected.

```text
[offline] scripted model, no API key needed

1. alert record (ticket will be granted from this, not the model)
    Alert ALR-2291 (P2): web-checkout p99 latency 4.8s over 5m (threshold 1.5s). Service: web-checkout.

2. standing role (no ticket yet)
    coordinator role: key 1bc63b81ab38..
      ttl 3600s, holder PublicKey(1bc63b81...)
      page_oncall(reason=Wildcard())
      read_logs(service=Pattern('*'))
      restart_service(service=Pattern('web-*'))
      scale_service(replicas=Range(min=1.0, max=10.0), service=Pattern('web-*'))
      transfer_to_agent(agent_name=OneOf(['remediation_agent']))
    remediation_agent: no ticket (granted at transfer_to_agent, from the alert record)

3. ticket granted at hand-off
    remediation ticket: key 8b0f36c027c4..
      ttl 600s, holder PublicKey(8b0f36c0...)
      read_logs(service=Exact('web-checkout'))
      scale_service(replicas=Range(min=1.0, max=4.0), service=Exact('web-checkout'))
      delegation receipt: DelegationReceipt(parent='tnu_wrt_01a0b6a9a6407953b82b1eed5cf29b3a', child='tnu_wrt_01a0b6a9a6ed72e3acd378b27c5f3839')

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

10. receipts: one signed record per gateway decision
    6 receipts, all signed by gateway key 461e74921c23..: ['allow:ok', 'allow:ok', 'allow:ok', 'deny:constraint_violation', 'deny:constraint_violation', 'deny:tool_not_authorized']
    tampered receipt -> ValidationError

11. above the ticket: the role allows it only with an approval
    coordinator asks for 6 -> ApprovalGateTriggered: Approval required for tool 'scale_service'
    with sre-lead's signed approval -> {'service': 'web-checkout', 'replicas': 6, 'previous': 3}
    a stranger's approval -> InvalidApproval: Invalid approval: approver not in trusted set

RESULT: OK
```

Sections 1 to 6 are the run itself: the alert, the role, the ticket
granted at hand-off, and what the gateway decided. The fleet snapshot
after section 5 is the point of the recipe: one service changed, by
the amount the ticket allowed, and nothing else moved.

Sections 7 to 9 run outside the agent loop against the same verifier
the gateway uses. They cover the three ways a warrant could reach the
gateway that the run does not exercise: copied to another agent, widened
by its holder, or issued by someone the platform never trusted.

Section 10 verifies every receipt from the run offline, confirms the
signer is the gateway's key, and shows that a receipt with eight
characters changed does not verify. Section 11 shows the approval gate:
the coordinator asks for six replicas and is refused, the SRE lead
signs an approval bound to that exact request, the same call then
executes, and an approval signed by anyone else is rejected.

## What this does and does not defend against

The adversary is the agent: a sub-agent steered by content it read into
asking for something outside its ticket. Against that, the check holds
at the gateway for every fleet change, once per call, for the hand-off
as well as the tools, and against authority rather than content. The
gateway takes no view on whether scaling to three was the right fix.

It does not defend against an attacker with code execution in the same
process, who could read the holder keys out of `OnCallAuthority`. In a
deployment each agent process holds only its own key, the platform key
stays with whatever provisions agents, and the gateway process is given
the public root. `provision()` generates all the keys in one place so
the recipe runs by itself, then drops the platform's private key.

A gateway in its own process should also add replay protection; the
library ships a nonce store for that. Here the single-use proof
registry serves the same purpose within one process.

## Adapting it

- Replace the fleet methods in `FleetGateway._execute` with your own
  side effects, and give every argument of every tool a constraint in
  `mint_role()` and `grant_ticket()`. An argument the warrant does not
  name is refused as an unknown field, which is the safe failure but a
  surprising one the first time.
- Keep ticket issuance on the hand-off path and read the scope from
  your task record (an alert, a support ticket, an order). Never take
  it from model output.
- Move `FleetGateway` into the process that owns the side effect. Send
  `encode_warrant_stack(chain)` and the signature with the call, and
  construct the gateway there with the platform's public key. A warrant
  chain is a self-contained proof, so nothing else needs to travel.
- Put floors as well as ceilings in the warrant. `Range(1, 4)` is a
  ticket; a range with no minimum is a ticket that permits scaling to
  zero.
- The arguments signed must be the arguments verified, including their
  types. `"3"` and `3` are different values, and the plugin does not
  coerce them.

## Files

| Path | What it holds |
|---|---|
| `app/authority.py` | The standing role, per-agent keys, and ticket issuance |
| `app/alert.py` | The trusted alert record the ticket is built from |
| `app/plugin.py` | The holder side: sign each call, grant the ticket on transfer |
| `app/gateway.py` | The resource side: verify, run the tool, sign a receipt |
| `app/tools.py` | Thin ADK tool wrappers that present the proof to the gateway |
| `app/agent.py` | The agent tree and `build_app()` |
| `app/prompt.py` | Instructions for both agents |
| `demo.py` | The scripted run plus the checks in sections 7 to 11 |
| `tests/` | Runnability and enforcement tests, all offline |

Checked against `google-adk` 2.9.1, `tenuo` 0.3.0, Python 3.11.

## License

Apache-2.0, matching this repository and the library.
