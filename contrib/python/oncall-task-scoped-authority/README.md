# Task-scoped authority for an on-call agent team

An on-call coordinator hands a production alert to a remediation agent.
The logs contain an injected instruction to scale the wrong services and
restart payments. One legitimate scale succeeds; every action outside the
alert's scope is refused before the fleet changes.

The recipe demonstrates task-scoped authority with signed **warrants** from
[tenuo](https://github.com/tenuo-ai/tenuo), an Apache-2.0 library:

- A **role** is the coordinator's standing warrant.
- A **ticket** is a narrower warrant for one alert and one remediation agent.
- A **gateway** verifies the ticket and exact tool arguments where the fleet
  changes.

```text
platform -> standing role -> coordinator -> task ticket -> remediation agent
                                                          |
                                                    signed tool call
                                                          |
                                                          v
                                                   fleet gateway
```

## Setup

Run from this recipe's directory with Python 3.11 or newer and
[uv](https://github.com/astral-sh/uv):

```bash
uv sync
```

The default run is offline. It needs no API key or cloud project.

## Run

```bash
uv run python demo.py
uv run pytest
```

The demo uses a scripted model but the real ADK `Runner`, agent-transfer
flow, callbacks, plugin manager, session service, and tools.

## Expected result

The remediation agent follows the injected log line. The gateway permits the
one call covered by its ticket and denies the rest:

```text
ALLOWED  scale_service(web-checkout, 3)
DENIED   scale_service(web-checkout, 50)
DENIED   scale_service(db-primary, 4)
DENIED   restart_service(web-payments)

fleet after: web-checkout=3, web-payments=3, db-primary=1
RESULT: OK
```

The remainder of the demo exercises delegation, expiry, signed receipts, and
approval gates against the same verifier.

## Authority flow

The code in `app/` follows these five steps.

### 1. Provision the standing role

In `app/authority.py`, a platform key mints a role to the coordinator's key.
The role permits the coordinator to:

- read any logs;
- scale or restart `web-*` services;
- scale between one and ten replicas;
- page the secondary on-call; and
- transfer work to the remediation agent.

Scaling to five or more replicas also requires approval from the SRE lead.
After minting, the recipe discards the platform's private key. The gateway
receives only its public key.

### 2. Receive the alert

`app/alert.py` contains alert `ALR-2291` for `web-checkout`. The model can
read and discuss the alert, but it does not choose the ticket's scope. The
service name comes from this trusted record.

### 3. Grant a ticket during hand-off

In ADK, `transfer_to_agent` is a tool call. `app/plugin.py` verifies that the
coordinator's role permits the transfer and then grants the remediation agent
a ticket for:

- `read_logs(service="web-checkout")`;
- `scale_service(service="web-checkout", replicas=1..4)`;
- ten minutes; and
- the remediation agent's public key.

The ticket is terminal, so the remediation agent cannot delegate it again.
It does not include `restart_service` or `transfer_to_agent`. Until the
hand-off succeeds, the remediation agent has no authority.

Granting is itself checked. A ticket that adds a tool, widens a service
pattern, or raises a replica ceiling is refused. A requested lifetime longer
than the role's remaining lifetime is clamped to the role.

### 4. Sign the exact tool call

For every fleet call, `app/plugin.py` signs the exact arguments ADK is about
to pass with the calling agent's key. A single-use registry stores the proof
under ADK's function-call ID. The bound wrapper in `app/tools.py` takes that
proof once and sends it with the warrant chain to the gateway. Proofs never
enter session state.

Each `App` receives its own bound tool object, proof registry, and gateway;
multiple app instances in one process do not share tool bindings.

### 5. Verify before changing the fleet

`FleetGateway.invoke` in `app/gateway.py` is the only path that changes
replica counts. It verifies:

- the chain begins at the platform's public key;
- every delegation link is valid and unexpired;
- the leaf warrant permits the requested tool and argument values; and
- the signature belongs to the leaf warrant's holder.

The gateway executes the tool only after all checks pass. A failure becomes a
tool result that ADK returns to the model, and the fleet remains unchanged.
Without the plugin, the wrapper presents no proof and the gateway refuses the
call.

| Side | Object | Holds | Responsibility |
|---|---|---|---|
| Holder | `InvocationPlugin` | The role and one signing key per agent | Authorize hand-off and sign exact tool arguments |
| Resource | `FleetGateway` | The public root, receipt key, and fleet | Verify authority, execute allowed tools, and record decisions |

## Why use a warrant?

The requirement is: *this service, between one and four replicas, for the
next ten minutes, checked where the fleet changes*.

- A system prompt cannot enforce it because injected content is also input to
  the model.
- A tool allowlist cannot constrain
  `scale_service("db-primary", 4)` when `scale_service` itself is allowed.
- A shared API key identifies a process, not an agent or delegation chain.
- A static role describes what on-call may do generally, not what this agent
  may do for this alert.

A warrant combines the tool, argument constraints, holder key, expiry, and
delegation chain in one signed object. Authority can only narrow as it is
passed on, and the resource that performs the action verifies it.

## Additional safeguards

The demo and tests cover more than the central injected-log scenario.

### Delegation and identity

- A ticket copied to an agent with a different key fails proof-of-possession.
- A ticket wider than its parent role fails during grant.
- A terminal ticket cannot be delegated again.
- A warrant from an unknown issuer fails because its root is not trusted.
- An expired ticket fails even if its signature is otherwise valid.

The ticket's delegation receipt records its parent, child, and intent:
`remediate ALR-2291 on web-checkout`.

### Signed decision receipts

The gateway signs every allow or denial produced by completed warrant
verification. `tenuo_core.verify_receipt` verifies the receipt offline; the
reader also compares its signer with the gateway's published receipt key.

A call with no warrant, or with a signed envelope that does not match the tool
and arguments received, is rejected before warrant verification. That
structural rejection stays in the ordinary decision log because there is no
completed authority decision for a receipt to commit to.

### Approval above the ticket

The standing role permits up to ten replicas, but five or more requires a
signed approval from the SRE lead in addition to the coordinator's signature.
The remediation ticket stops at four, so the remediation agent is denied
above four rather than paused for approval. The demo separately shows the
coordinator's six-replica call failing without the named approver, succeeding
with the SRE lead, and rejecting a stranger's approval.

## Run with a live model

Copy the environment template and set `MODEL_NAME` plus either Google AI
Studio or Vertex AI credentials:

```bash
cp .env.example .env
uv run python demo.py --live
uv run adk run app        # or: uv run adk web
```

A live model may or may not follow the injected instruction. The gateway's
answer is the same either way. `adk run` and `adk web` load one module-level
app per process; tickets are granted per session at hand-off.

## Trust boundary

The adversary is an agent steered by content it read into requesting an action
outside its ticket. Fleet calls are enforced at the gateway immediately
before the side effect. The `transfer_to_agent` hand-off is enforced by the
plugin before it grants a ticket. Neither check tries to decide whether
scaling to three is a good remediation; they decide only whether the caller
has authority to request it.

The recipe does not defend against an attacker with code execution in the
same process, who could read holder keys from `OnCallAuthority`. A deployment
should give each agent process only its own key, keep the platform key with
the provisioning service, and put `FleetGateway` in the process that owns the
side effect. `provision()` creates everything together only to make the recipe
self-contained, then discards the platform's private key.

An external gateway should also use persistent replay protection. The library
ships a nonce store; this single-process recipe uses a single-use proof
registry keyed by ADK's function-call ID.

## Adapting the recipe

- Replace `FleetGateway._execute` with your side effects, and constrain every
  tool argument in `mint_role()` and `grant_ticket()`. An argument omitted
  from the warrant is refused.
- Build tickets from a trusted task record, such as an alert, support ticket,
  or order. Never build their scope from model output.
- Move `FleetGateway` to the resource process. Send the encoded warrant chain
  and signature with the call, and configure the gateway with the platform's
  public key.
- Put floors as well as ceilings in numeric constraints. `Range(1, 4)` is a
  ticket; a range without a minimum may permit scaling to zero.
- Preserve argument types. Signed values `"3"` and `3` are different, and the
  plugin does not coerce them.

## Files

| Path | Purpose |
|---|---|
| `app/authority.py` | Mint the standing role and issue per-alert tickets |
| `app/alert.py` | Supply the trusted alert record |
| `app/plugin.py` | Authorize hand-off and sign each agent's calls |
| `app/gateway.py` | Verify authority, execute tools, and sign receipts |
| `app/tools.py` | Bind ADK tool wrappers to one app's gateway and proofs |
| `app/agent.py` | Build the agent tree and ADK app |
| `app/prompt.py` | Define instructions for both agents |
| `demo.py` | Run the scripted scenario and additional security checks |
| `tests/` | Assert runnability and enforcement without network access |

Checked against `google-adk` 2.9.1, `tenuo` 0.3.0, and Python 3.11.

## License

Apache-2.0.
