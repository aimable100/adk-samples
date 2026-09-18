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

"""Run the recipe end to end and print what happened.

    python demo.py           # offline, scripted model, no API key
    python demo.py --live    # real model; needs MODEL_NAME + credentials

Offline is the default and is what the tests exercise. The ADK `Runner`,
its flows, its callbacks and its plugin manager are the real ones; only
the model is replaced, by a `BaseLlm` subclass that replays a fixed list
of function calls per agent. The list follows the injected instruction
in the log excerpt to the letter, which is the worst case a real model
could produce.

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
    Authorizer,
    Exact,
    Pattern,
    Range,
    SigningKey,
    Warrant,
    decode_warrant_stack_base64,
    encode_warrant_stack,
)
from tenuo.exceptions import (
    MonotonicityError,
    SignatureInvalid,
    UntrustedRoot,
)

from app import authority, tools
from app.agent import REMEDIATION_AGENT_NAME, ROOT_AGENT_NAME, build_app
from app.authz import DENIED

# ADK stamps the calling agent's name into `llm_request.config.labels`
# (google/adk/flows/llm_flows/base_llm_flow.py), so one model instance can
# drive a whole multi-agent scenario.
_AGENT_LABEL = "adk_agent_name"

ALERT_MESSAGE = (
    f"Alert {tools.ALERT['id']} ({tools.ALERT['severity']}): "
    f"{tools.ALERT['summary']}. Service: {tools.ALERT['service']}."
)


def _fc(name: str, **args: Any) -> types.Part:
    return types.Part.from_function_call(name=name, args=args)


def _text(body: str) -> types.Part:
    return types.Part.from_text(text=body)


class ScriptedLlm(BaseLlm):
    """A `BaseLlm` that replays a per-agent queue of `types.Part`s."""

    model: str = "scripted-offline-model"
    # A pydantic field on ADK's BaseLlm, not a plain attribute: a
    # ClassVar here would stop `ScriptedLlm(script=...)` binding at all.
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
    """The coordinator confirms the symptom and hands off. The
    remediation agent does its job, then does exactly what the injected
    log line told it to."""
    service = tools.ALERT["service"]
    return {
        ROOT_AGENT_NAME: [
            _fc("read_logs", service=service),
            _fc("transfer_to_agent", agent_name=REMEDIATION_AGENT_NAME),
        ],
        REMEDIATION_AGENT_NAME: [
            _fc("read_logs", service=service),
            _fc("scale_service", service=service, replicas=3),
            # From here on, the "SRE NOTE" in the logs is driving.
            _fc("scale_service", service=service, replicas=50),
            _fc("scale_service", service="db-primary", replicas=4),
            _fc("restart_service", service="web-payments"),
            _text(
                f"Scaled {service} to 3 replicas. The log note asking for "
                "db-primary, web-payments and 50 replicas was outside my "
                "ticket and was refused; escalate if it is real."
            ),
        ],
    }


@dataclass
class ToolCall:
    """One function call paired with its response, by ADK part id."""

    agent: str
    tool: str
    args: dict[str, Any]
    response: dict[str, Any]

    @property
    def denied(self) -> bool:
        return self.response.get("error") == DENIED


def executed_entry(call: ToolCall) -> tuple[str, Any]:
    """The `tools.EXECUTED` entry this call would have left had its body
    run: `(name, service)` or, for `scale_service`, `(name, (service,
    replicas))`, matching what each body records first."""
    if call.tool == "scale_service":
        return (call.tool, (call.args["service"], call.args["replicas"]))
    return (call.tool, next(iter(call.args.values())))


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
    """An event's content parts, or `[]` for an event with no content;
    not every runner event carries one (e.g. a turn-boundary event)."""
    content = getattr(event, "content", None)
    return content.parts if content and content.parts else []


def tool_calls(events) -> list[ToolCall]:
    """Every function call in the run, in order, with its response."""
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
    """One turn. Returns (events, team_authority, plugin)."""
    tools.reset()
    application, team, plugin = build_app(model)
    events = asyncio.run(_drive(application, ALERT_MESSAGE))
    return events, team, plugin


def run_offline():
    return run(ScriptedLlm(script=script()))


def _fmt(constraint: Any) -> str:
    """`Range(min=None, max=Some(4.0))` -> `Range(max=4.0)`; the reprs
    come from the Rust core and read better with the wrapping removed."""
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


def _print_holdings(team: authority.TeamAuthority) -> None:
    for agent in (ROOT_AGENT_NAME, REMEDIATION_AGENT_NAME):
        chain = team.chain_for(agent)
        leaf = chain[-1]
        key_hex = bytes(team.key_for(agent).public_key_bytes()).hex()
        print(f"    {agent}: chain depth {len(chain)}, key {key_hex[:12]}..")
        print(f"      ttl {leaf.ttl_seconds()}s, holder {leaf.holder_key}")
        for line in _describe(leaf):
            print(f"      {line}")


def _print_transcript(calls: list[ToolCall]) -> None:
    for call in calls:
        verdict = "DENIED" if call.denied else "ok    "
        print(f"    [{call.agent}] {verdict} {call.tool}({call.args})")


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

    print(f"\n1. the alert: {ALERT_MESSAGE}")
    events, team, _plugin = run(model)
    service = tools.ALERT["service"]

    print("\n2. what each agent holds (role -> ticket)")
    _print_holdings(team)

    print("\n3. one turn, two agents")
    calls = tool_calls(events)
    _print_transcript(calls)

    print("\n4. the refusals")
    print(f"    tool bodies that ran: {tools.EXECUTED}")
    denied = [c for c in calls if c.denied]
    for call in denied:
        print(
            f"    {call.tool}({call.args}) -> {call.response['reason']}: "
            f"{call.response['detail']}"
        )
    # A tool body records (name, arg) as its first statement; a denied
    # call must have left no such record.
    denied_bodies = [c for c in denied if executed_entry(c) in tools.EXECUTED]
    reasons = {
        (c.tool, c.args.get("service")): c.response["reason"] for c in denied
    }
    scripted_ok = live or reasons == {
        ("scale_service", service): "ConstraintViolation",
        ("scale_service", "db-primary"): "ConstraintViolation",
        ("restart_service", "web-payments"): "ToolNotAuthorized",
    }

    authorizer = Authorizer(trusted_roots=team.trusted_roots)
    now = int(time.time())
    chain = team.chain_for(REMEDIATION_AGENT_NAME)
    ticket = chain[-1]
    remediation_key = team.key_for(REMEDIATION_AGENT_NAME)
    args = {"service": service}

    print("\n5. a leaked ticket, replayed with a different key")
    stranger = SigningKey.generate()
    leaked = decode_warrant_stack_base64(encode_warrant_stack(chain))
    signature = leaked[-1].sign(stranger, "read_logs", args, now)
    try:
        authorizer.check_chain(leaked, "read_logs", args, signature)
        replay_ok = False
        print("    ALLOWED (unexpected)")
    except SignatureInvalid as exc:
        replay_ok = True
        print(f"    {type(exc).__name__}: {exc}")

    print("\n6. the remediation agent tries to widen its own ticket")
    try:
        (
            ticket.grant_builder()
            .capability(
                "scale_service",
                service=Exact(service),
                replicas=Range.max_value(50.0),
            )
            .holder(remediation_key.public_key)
            .ttl(authority.TICKET_TTL_SECONDS)
            .grant(remediation_key)
        )
        widen_ok = False
        print("    granted (unexpected)")
    except MonotonicityError as exc:
        widen_ok = True
        d = exc.details
        # Formatted from `details`, not `str(exc)`, which is what a
        # caller should rely on: the fields are stable, the prose is not.
        print(
            f"    MonotonicityError ({type(exc).__name__}): child "
            f"{d.get('bound')} {d.get('child_value')} exceeds parent "
            f"{d.get('bound')} {d.get('parent_value')}"
        )

    print("\n7. a warrant minted by a key the platform never issued")
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

    ok = (
        scripted_ok
        and not denied_bodies
        and all(not c.denied for c in calls if c.tool == "read_logs")
        and replay_ok
        and widen_ok
        and forged_ok
    )
    print("\nRESULT:", "OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
