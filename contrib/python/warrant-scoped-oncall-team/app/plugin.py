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

"""Holder side: sign each fleet call, grant the ticket at hand-off.

For fleet tools the plugin signs the exact arguments ADK is about to
pass and registers the proof under the call's ``function_call_id``. The
tool body takes the proof once and presents it to `FleetGateway`. Proofs
never touch session state.

`transfer_to_agent` is an ADK framework tool, so the plugin authorizes
the transfer against the role and grants the ticket in the same
callback. The service name comes from the alert record, not from the
model's transfer arguments.
"""

from __future__ import annotations

import time
from typing import Any

from google.adk.plugins.base_plugin import BasePlugin
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.tool_context import ToolContext
from tenuo import Authorizer, decode_warrant_stack_base64, encode_warrant_stack
from tenuo.exceptions import TenuoError

from .authority import REMEDIATION_AGENT_NAME, OnCallAuthority
from .gateway import DENIED, Decision, ProofRegistry, SignedInvocation

# The ticket persists for the session, as a base64 chain in state.
TICKET_STACK_KEY = "__tenuo_ticket_stack__"


def _business_args(tool_args: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in dict(tool_args).items() if k != "tool_context"}


def _session_id(tool_context: ToolContext) -> str | None:
    """The session this call belongs to, or None. None means no ticket."""
    session = getattr(tool_context, "session", None)
    if session is not None and getattr(session, "id", None):
        return str(session.id)
    invocation = getattr(tool_context, "_invocation_context", None)
    if invocation is not None:
        session = getattr(invocation, "session", None)
        if session is not None and getattr(session, "id", None):
            return str(session.id)
    return None


def _state_get(tool_context: ToolContext, key: str, default: Any = None) -> Any:
    state = tool_context.state
    getter = getattr(state, "get", None)
    if callable(getter):
        return getter(key, default)
    try:
        return state[key]
    except (KeyError, TypeError):
        return default


def _state_set(tool_context: ToolContext, key: str, value: Any) -> None:
    tool_context.state[key] = value


class InvocationPlugin(BasePlugin):
    """Sign each fleet call; grant a ticket when the coordinator hands off."""

    def __init__(
        self,
        authority: OnCallAuthority,
        alert: dict[str, Any],
        name: str = "invocation",
    ):
        super().__init__(name=name)
        self._authority = authority
        self._alert = alert
        self._authorizer = Authorizer(trusted_roots=authority.trusted_roots)
        self.proofs = ProofRegistry()
        self.handoffs: list[Decision] = []

    def _chain(
        self,
        agent: str,
        session_id: str | None,
        tool_context: ToolContext | None = None,
    ) -> list | None:
        if agent == REMEDIATION_AGENT_NAME and tool_context is not None:
            stack = _state_get(tool_context, TICKET_STACK_KEY)
            if stack:
                return list(decode_warrant_stack_base64(stack))
        return self._authority.chain_for(agent, session_id)

    def sign(
        self,
        agent: str,
        tool: str,
        args: dict[str, Any],
        session_id: str | None,
        tool_context: ToolContext | None = None,
    ) -> SignedInvocation | None:
        chain = self._chain(agent, session_id, tool_context)
        if chain is None:
            return None
        key = self._authority.key_for(agent)
        signature = chain[-1].sign(key, tool, args, int(time.time()))
        return SignedInvocation(agent, tool, args, chain, signature)

    def grant_from_alert(self, session_id: str) -> list:
        """Create the ticket from the alert record for this session."""
        return self._authority.issue_ticket(self._alert["service"], session_id)

    async def before_tool_callback(
        self,
        *,
        tool: BaseTool,
        tool_args: dict[str, Any],
        tool_context: ToolContext,
    ) -> dict[str, Any] | None:
        args = _business_args(tool_args)
        session_id = _session_id(tool_context)
        agent = tool_context.agent_name
        if tool.name == "transfer_to_agent":
            return self._handoff(agent, args, tool_context, session_id)
        invocation = self.sign(agent, tool.name, args, session_id, tool_context)
        call_id = getattr(tool_context, "function_call_id", None)
        if invocation is not None and call_id is not None:
            self.proofs.put(call_id, invocation)
        return None

    async def after_tool_callback(
        self,
        *,
        tool: BaseTool,
        tool_args: dict[str, Any],
        tool_context: ToolContext,
        result: dict[str, Any],
    ) -> dict[str, Any] | None:
        # Drop any proof the tool body did not take.
        self.proofs.discard(getattr(tool_context, "function_call_id", None))
        return None

    def _handoff(
        self,
        agent: str,
        args: dict[str, Any],
        tool_context: ToolContext,
        session_id: str | None,
    ) -> dict[str, Any] | None:
        invocation = self.sign(agent, "transfer_to_agent", args, session_id)
        if invocation is None or session_id is None:
            return self._refuse(
                agent,
                "transfer_to_agent",
                args,
                "NoWarrant",
                f"no warrant chain is registered for agent '{agent}'",
            )
        try:
            self._authorizer.check_chain(
                invocation.chain,
                "transfer_to_agent",
                args,
                invocation.signature,
            )
        except TenuoError as exc:
            return self._refuse(
                agent,
                "transfer_to_agent",
                args,
                type(exc).__name__,
                str(exc),
            )
        chain = self.grant_from_alert(session_id)
        _state_set(tool_context, TICKET_STACK_KEY, encode_warrant_stack(chain))
        self.handoffs.append(
            Decision(agent, "transfer_to_agent", dict(args), True, "ok")
        )
        return None

    def _refuse(
        self,
        agent: str,
        tool: str,
        args: dict[str, Any],
        reason: str,
        detail: str,
    ) -> dict[str, Any]:
        self.handoffs.append(Decision(agent, tool, args, False, reason))
        return {
            "error": DENIED,
            "agent": agent,
            "tool": tool,
            "reason": reason,
            "detail": detail,
        }
