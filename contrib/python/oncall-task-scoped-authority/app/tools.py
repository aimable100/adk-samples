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

"""ADK tool wrappers. Each body presents its proof to the gateway.

The wrappers take the arguments ADK passed in, take the proof the plugin
registered for this call, and hand both to `FleetGateway.invoke`. A
missing plugin, a missing ticket, or a proof of other arguments fails
closed there.

`tool_context` is injected by ADK and is not visible to the model.
"""

from __future__ import annotations

from typing import Any

from google.adk.tools.tool_context import ToolContext

from .gateway import FleetGateway, ProofRegistry, SignedInvocation


class FleetTools:
    """Fleet tool wrappers bound to one App's gateway and proof registry."""

    def __init__(self, gateway: FleetGateway, proofs: ProofRegistry) -> None:
        self.gateway = gateway
        self._proofs = proofs

    def _invocation(
        self, tool_context: ToolContext | None
    ) -> SignedInvocation | None:
        if tool_context is None:
            return None
        return self._proofs.take(
            getattr(tool_context, "function_call_id", None)
        )

    def _invoke(
        self,
        tool: str,
        args: dict[str, Any],
        tool_context: ToolContext | None,
    ) -> dict:
        return self.gateway.invoke(tool, args, self._invocation(tool_context))

    def read_logs(
        self, service: str, tool_context: ToolContext | None = None
    ) -> dict:
        """Return the most recent log lines for a service.

        Args:
            service: the service name, e.g. "web-checkout".
        """
        return self._invoke("read_logs", {"service": service}, tool_context)

    def scale_service(
        self,
        service: str,
        replicas: int,
        tool_context: ToolContext | None = None,
    ) -> dict:
        """Set the replica count of a service.

        Args:
            service: the service to scale.
            replicas: the desired replica count. Must be a positive integer.
        """
        return self._invoke(
            "scale_service",
            {"service": service, "replicas": replicas},
            tool_context,
        )

    def restart_service(
        self, service: str, tool_context: ToolContext | None = None
    ) -> dict:
        """Rolling-restart every replica of a service.

        Args:
            service: the service to restart.
        """
        return self._invoke(
            "restart_service", {"service": service}, tool_context
        )

    def page_oncall(
        self, reason: str, tool_context: ToolContext | None = None
    ) -> dict:
        """Page the secondary on-call engineer.

        Args:
            reason: a one-line summary for the page.
        """
        return self._invoke("page_oncall", {"reason": reason}, tool_context)
