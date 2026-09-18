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

"""The only authorization code in the recipe: one ADK plugin.

`WarrantChainPlugin.before_tool_callback` runs before every tool call
in the tree, including ADK's own `transfer_to_agent`. It looks up the
calling agent's warrant chain and key, signs the exact arguments the
tool is about to receive with that key, and verifies the signature and
the whole chain against the trusted platform root. If anything fails it
returns a small error dict, which ADK uses as the tool's result instead
of running the body (`google/adk/flows/llm_flows/_tool_caller.py`).

The verifier is wired directly here rather than through the library's
stock ADK plugin, because that plugin holds one signing key for the
process and this recipe gives each agent its own.
"""

import time
from dataclasses import dataclass
from typing import Any

from google.adk.plugins.base_plugin import BasePlugin
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.tool_context import ToolContext
from tenuo import Authorizer
from tenuo.exceptions import TenuoError

from .authority import TeamAuthority

DENIED = "authority_denied"


@dataclass(frozen=True)
class Decision:
    """One authorization decision, kept so a run can be inspected."""

    agent: str
    tool: str
    args: dict[str, Any]
    allowed: bool
    reason: str


class WarrantChainPlugin(BasePlugin):
    """Sign each tool call with the calling agent's key; verify the chain."""

    def __init__(self, authority: TeamAuthority, name: str = "warrant_chain"):
        super().__init__(name=name)
        self._authority = authority
        self._authorizer = Authorizer(trusted_roots=authority.trusted_roots)
        self.decisions: list[Decision] = []

    def authorize(
        self, agent: str, tool: str, args: dict[str, Any]
    ) -> dict[str, Any] | None:
        """`None` if the call may proceed, otherwise the refusal to
        return in place of the tool's result."""
        args = dict(args)
        if agent not in self._authority.chains:
            return self._deny(
                agent,
                tool,
                args,
                "NoWarrant",
                f"no warrant chain is registered for agent '{agent}'",
            )

        chain = self._authority.chain_for(agent)
        key = self._authority.key_for(agent)
        try:
            # The signature covers the tool name, the arguments as they
            # are, and the time. It is checked against the leaf warrant's
            # holder key, so a chain copied out of another agent fails.
            signature = chain[-1].sign(key, tool, args, int(time.time()))
            self._authorizer.check_chain(chain, tool, args, signature)
        except TenuoError as exc:
            return self._deny(agent, tool, args, type(exc).__name__, str(exc))

        self.decisions.append(Decision(agent, tool, args, True, "ok"))
        return None

    async def before_tool_callback(
        self,
        *,
        tool: BaseTool,
        tool_args: dict[str, Any],
        tool_context: ToolContext,
    ) -> dict[str, Any] | None:
        return self.authorize(tool_context.agent_name, tool.name, tool_args)

    def _deny(
        self,
        agent: str,
        tool: str,
        args: dict[str, Any],
        reason: str,
        detail: str,
    ) -> dict[str, Any]:
        self.decisions.append(Decision(agent, tool, args, False, reason))
        return {
            "error": DENIED,
            "agent": agent,
            "tool": tool,
            "reason": reason,
            "detail": detail,
        }
