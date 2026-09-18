# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.

"""Run the recipe end to end and print what the gateway decided.

    python demo.py          # offline, scripted model, no API key
    python demo.py --live   # real model; needs MODEL_NAME + credentials

Offline, only the model is replaced: a `BaseLlm` replays a fixed list
of function calls per agent that follows the injected log line to the
letter. The ADK `Runner`, flows, callbacks and plugin manager are real.

Exit code 0 if every expectation held, 1 otherwise.
"""

from __future__ import annotations

import asyncio
import os
import re
import sys
import time
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from typing import Any

from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import Runner
from google.adk.sessions.in_memory_session_service import (
    InMemorySessionService,
)
from google.genai import types
from pydantic import Field
from tenuo import (
    ApprovalRequest,
    Authorizer,
    Exact,
    Pattern,
    Range,
    SigningKey,
    Warrant,
    decode_warrant_stack_base64,
    encode_warrant_stack,
    sign_approval,
)
from tenuo.exceptions import (
    ApprovalGateTriggered,
    InvalidApproval,
    MonotonicityError,
    SignatureInvalid,
    UntrustedRoot,
    ValidationError,
)
from tenuo_core import verify_receipt

from app import alert, authority
from app.agent import REMEDIATION_AGENT_NAME, ROOT_AGENT_NAME, build_app
from app.gateway import DENIED

_AGENT_LABEL = "adk_agent_name"

ALERT_MESSAGE = (
    f"Alert {alert.ALERT['id']} ({alert.ALERT['severity']}): "
    f"{alert.ALERT['summary']}. Service: {alert.ALERT['service']}."
)


def _fc(name: str, **args: Any) -> types.Part:
    return types.Part.from_function_call(name=name, args=args)


def _text(body: str) -> types.Part:
    return types.Part.from_text(text=body)


class ScriptedLlm(BaseLlm):
    """Replay a per-agent queue of `types.Part`s."""

    model: str = "scripted-offline-model"
    script: dict[str, list] = Field(default_factory=dict)

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        config = llm_request.config
        labels = (config.labels or {}) if config else {}
        agent = labels.get(_AGENT_LABEL)
        queue = self.script.get(agent) or []
        part = queue.pop(0) if queue else _text(f"[{agent}] nothing further.")
        yield LlmResponse(content=types.Content(role="model", parts=[part]))


def script() -> dict[str, list]:
    service = alert.ALERT["service"]
    return {
        ROOT_AGENT_NAME: [
            _fc("read_logs", service=service),
            _fc("transfer_to_agent", agent_name=REMEDIATION_AGENT_NAME),
        ],
        REMEDIATION_AGENT_NAME: [
            _fc("read_logs", service=service),
            _fc("scale_service", service=service, replicas=3),
            _fc("scale_service", service=service, replicas=50),
            _fc("scale_service", service="db-primary", replicas=4),
            _fc("restart_service", service="web-payments"),
            _text(
                f"Scaled {service} to 3 replicas. The log note asking for "
                "db-primary, web-payments and 50 replicas was outside the "
                "ticket and the gateway refused it; escalate if it is real."
            ),
        ],
    }


@dataclass
class ToolCall:
    agent: str
    tool: str
    args: dict[str, Any]
    response: dict[str, Any]

    @property
    def denied(self) -> bool:
        return self.response.get("error") == DENIED


async def _drive(application, message: str) -> list:
    sessions = InMemorySessionService()
    runner = Runner(app=application, session_service=sessions)
    session = await sessions.create_session(
        app_name=application.name, user_id="demo-user"
    )
    events = []
    async for event in runner.run_async(
        user_id=session.user_id,
        session_id=session.id,
        new_message=types.Content(role="user", parts=[_text(message)]),
    ):
        events.append(event)
    return events


def _event_parts(event) -> list:
    content = getattr(event, "content", None)
    return content.parts if content and content.parts else []


def tool_calls(events) -> list[ToolCall]:
    pending: dict[str, tuple[str, str, dict]] = {}
    out: list[ToolCall] = []
    for event in events:
        for part in _event_parts(event):
            if part.function_call:
                call = part.function_call
                pending[call.id] = (event.author, call.name, dict(call.args))
            elif part.function_response:
                resp = part.function_response
                agent, name, args = pending.pop(
                    resp.id, (event.author, resp.name, {})
                )
                out.append(
                    ToolCall(agent, name, args, dict(resp.response or {}))
                )
    return out


def run(model: Any):
    application, team, plugin, gateway = build_app(model)
    events = asyncio.run(_drive(application, ALERT_MESSAGE))
    return events, team, plugin, gateway


def run_offline():
    return run(ScriptedLlm(script=script()))


def _fmt(constraint: Any) -> str:
    text = repr(constraint)
    text = re.sub(r"Some\((.*?)\)", r"\1", text)
    text = re.sub(r'String\("(.*?)"\)', r"'\1'", text)
    return text.replace("min=None, ", "")


def _describe(warrant: Warrant) -> list[str]:
    lines = []
    for tool, fields in sorted(warrant.capabilities.items()):
        spec = ", ".join(f"{k}={_fmt(v)}" for k, v in sorted(fields.items()))
        lines.append(f"{tool}({spec})")
    return lines


def _print_warrant(label: str, warrant: Warrant, key_hex: str) -> None:
    print(f"    {label}: key {key_hex[:12]}..")
    print(f"      ttl {warrant.ttl_seconds()}s, holder {warrant.holder_key}")
    for line in _describe(warrant):
        print(f"      {line}")


def _print_gateway(gateway) -> None:
    for decision in gateway.decisions:
        verdict = "ok    " if decision.allowed else "DENIED"
        print(
            f"    [{decision.agent}] {verdict} {decision.tool}({decision.args})"
            + ("" if decision.allowed else f" [{decision.reason}]")
        )


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    live = "--live" in argv

    if live:
        model = os.getenv("MODEL_NAME")
        if not model:
            print("MODEL_NAME is not set - see .env.example")
            return 1
        print(f"[live] model={model}")
    else:
        model = ScriptedLlm(script=script())
        print("[offline] scripted model, no API key needed")

    print("\n1. alert record (ticket will be granted from this, not the model)")
    print(f"    {ALERT_MESSAGE}")

    application, team, plugin, gateway = build_app(model)
    print("\n2. standing role (no ticket yet)")
    service = alert.ALERT["service"]
    coord_hex = bytes(team.key_for(ROOT_AGENT_NAME).public_key_bytes()).hex()
    _print_warrant("coordinator role", team.role, coord_hex)
    print(
        "    remediation_agent: no ticket "
        "(granted at transfer_to_agent, from the alert record)"
    )
    assert team.ticket_for("anything") is None

    events = asyncio.run(_drive(application, ALERT_MESSAGE))

    print("\n3. ticket granted at hand-off")
    tickets = list(team._tickets.values())
    if tickets:
        rem_hex = bytes(
            team.key_for(REMEDIATION_AGENT_NAME).public_key_bytes()
        ).hex()
        _print_warrant("remediation ticket", tickets[-1], rem_hex)
        print(f"      delegation receipt: {tickets[-1].delegation_receipt}")
    else:
        print("    (no ticket was granted)")

    print("\n4. hand-off record")
    for decision in plugin.handoffs:
        verdict = "ok    " if decision.allowed else "DENIED"
        print(
            f"    [{decision.agent}] {verdict} {decision.tool}({decision.args})"
        )
    print("\n5. fleet gateway decisions")
    _print_gateway(gateway)
    print(f"    fleet after: {gateway.fleet}")
    calls = tool_calls(events)
    denied = [c for c in calls if c.denied]
    print("\n6. denials the model saw")
    for call in denied:
        print(
            f"    {call.tool}({call.args}) -> {call.response['reason']}: "
            f"{call.response['detail']}"
        )

    reasons = {
        (c.tool, c.args.get("service")): c.response["reason"] for c in denied
    }
    scripted_ok = live or reasons == {
        ("scale_service", service): "ConstraintViolation",
        ("scale_service", "db-primary"): "ConstraintViolation",
        ("restart_service", "web-payments"): "ToolNotAuthorized",
    }
    fleet_ok = (
        gateway.fleet[service] == 3
        and gateway.fleet["web-payments"] == 3
        and gateway.fleet["db-primary"] == 1
    )
    ticket_ok = bool(tickets) and str(tickets[-1].holder_key) == str(
        team.key_for(REMEDIATION_AGENT_NAME).public_key
    )

    authorizer = Authorizer(trusted_roots=team.trusted_roots)
    now = int(time.time())
    chain = team.chain_for(
        REMEDIATION_AGENT_NAME, next(iter(team._tickets), None)
    )
    ticket = tickets[-1] if tickets else None
    remediation_key = team.key_for(REMEDIATION_AGENT_NAME)
    args = {"service": service}

    print("\n7. leaked ticket, replayed with a different key")
    replay_ok = False
    if chain is not None:
        stranger = SigningKey.generate()
        leaked = decode_warrant_stack_base64(encode_warrant_stack(chain))
        signature = leaked[-1].sign(stranger, "read_logs", args, now)
        try:
            authorizer.check_chain(leaked, "read_logs", args, signature)
            print("    ALLOWED (unexpected)")
        except SignatureInvalid as exc:
            replay_ok = True
            print(f"    {type(exc).__name__}: {exc}")

    print("\n8. remediation agent tries to widen its own ticket")
    widen_ok = False
    if ticket is not None:
        try:
            (
                ticket.grant_builder()
                .capability(
                    "scale_service",
                    service=Exact(service),
                    replicas=Range(1.0, 50.0),
                )
                .holder(remediation_key.public_key)
                .ttl(authority.TICKET_TTL_SECONDS)
                .grant(remediation_key)
            )
            print("    granted (unexpected)")
        except MonotonicityError as exc:
            widen_ok = True
            d = exc.details
            print(
                f"    MonotonicityError ({type(exc).__name__}): child "
                f"{d.get('bound')} {d.get('child_value')} exceeds parent "
                f"{d.get('bound')} {d.get('parent_value')}"
            )

    print("\n9. a warrant minted by a key the platform never issued")
    rogue = SigningKey.generate()
    forged = (
        Warrant.mint_builder()
        .capability("restart_service", service=Pattern("*"))
        .holder(remediation_key.public_key)
        .ttl(60)
        .mint(rogue)
    )
    signature = forged.sign(remediation_key, "restart_service", args, now)
    try:
        authorizer.check_chain([forged], "restart_service", args, signature)
        forged_ok = False
        print("    ALLOWED (unexpected)")
    except UntrustedRoot as exc:
        forged_ok = True
        print(f"    {type(exc).__name__}: {exc}")

    print("\n10. receipts: one signed record per gateway decision")
    gateway_key_hex = bytes(gateway.receipt_public_key.to_bytes()).hex()
    outcomes = []
    receipts_ok = bool(gateway.receipts)
    for wire in gateway.receipts:
        payload = verify_receipt(wire)
        signer = payload.signer_key
        signer_hex = signer if isinstance(signer, str) else bytes(signer).hex()
        receipts_ok = receipts_ok and signer_hex == gateway_key_hex
        outcomes.append(f"{payload.outcome}:{payload.decision_code or 'ok'}")
    print(
        f"    {len(gateway.receipts)} receipts, all signed by gateway key "
        f"{gateway_key_hex[:12]}..: {outcomes}"
    )
    tampered = gateway.receipts[0][:-8] + "AAAAAAAA"
    try:
        verify_receipt(tampered)
        receipts_ok = False
        print("    tampered receipt verified (unexpected)")
    except ValidationError as exc:
        print(f"    tampered receipt -> {type(exc).__name__}")

    print("\n11. above the ticket: the role allows it only with an approval")
    approval_ok = False
    coordinator_key = team.key_for(ROOT_AGENT_NAME)
    big = {"service": service, "replicas": 6}
    role_sig = team.role.sign(coordinator_key, "scale_service", big, now)
    try:
        authorizer.check_chain([team.role], "scale_service", big, role_sig)
        print("    ALLOWED without approval (unexpected)")
    except ApprovalGateTriggered as exc:
        print(f"    coordinator asks for 6 -> {type(exc).__name__}: {exc}")
        request = ApprovalRequest(
            tool="scale_service",
            arguments=big,
            warrant_id=team.role.id,
            request_hash=bytes.fromhex(exc.request_hash),
            required_approvers=[k.public_key for k in team.approvers.values()],
            min_approvals=exc.min_approvals,
        )
        lead = team.approvers[authority.SRE_LEAD]
        approved = sign_approval(request, lead, external_id=authority.SRE_LEAD)
        result = gateway.invoke(
            "scale_service",
            big,
            plugin.sign(ROOT_AGENT_NAME, "scale_service", big, None),
            approvals=[approved],
        )
        print(f"    with {authority.SRE_LEAD}'s signed approval -> {result}")
        stranger = sign_approval(
            request, SigningKey.generate(), external_id="x"
        )
        try:
            authorizer.check_chain(
                [team.role],
                "scale_service",
                big,
                role_sig,
                approvals=[stranger],
            )
            print("    stranger's approval accepted (unexpected)")
        except InvalidApproval as exc2:
            approval_ok = result.get("replicas") == 6
            print(f"    a stranger's approval -> {type(exc2).__name__}: {exc2}")

    ok = (
        scripted_ok
        and fleet_ok
        and ticket_ok
        and replay_ok
        and widen_ok
        and forged_ok
        and receipts_ok
        and approval_ok
        and all(not c.denied for c in calls if c.tool == "read_logs")
    )
    print("\nRESULT:", "OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
