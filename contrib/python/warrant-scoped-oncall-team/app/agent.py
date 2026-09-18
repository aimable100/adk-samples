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

"""Coordinator + remediation agent, with holder-side signing and a fleet gateway.

The coordinator is provisioned with the standing on-call role. The
remediation agent starts with no ticket. `InvocationPlugin` grants that
ticket at `transfer_to_agent` from the alert record, then signs each
fleet call. `FleetGateway` is the only object that mutates the fleet,
and it is constructed with the platform public key alone.

If the plugin is left off, tools still run and the gateway refuses
every call: there is no signed invocation to present.
"""

import os
from typing import Any

from google.adk.agents.llm_agent import LlmAgent
from google.adk.apps.app import App

from . import alert as alert_mod
from . import authority, tools
from .gateway import FleetGateway
from .plugin import InvocationPlugin
from .prompt import COORDINATOR_PROMPT, REMEDIATION_PROMPT

APP_NAME = "warrant-scoped-oncall-team"
ROOT_AGENT_NAME = authority.COORDINATOR_AGENT_NAME
REMEDIATION_AGENT_NAME = authority.REMEDIATION_AGENT_NAME


def build_root_agent(model: Any) -> LlmAgent:
    """The agent tree. `model` is a model name or a `BaseLlm` instance."""
    remediation_agent = LlmAgent(
        name=REMEDIATION_AGENT_NAME,
        model=model,
        description="Applies a fix for one production alert.",
        instruction=REMEDIATION_PROMPT,
        tools=[tools.read_logs, tools.scale_service, tools.restart_service],
    )
    return LlmAgent(
        name=ROOT_AGENT_NAME,
        model=model,
        description="Triages production alerts and hands them off.",
        instruction=COORDINATOR_PROMPT,
        tools=[tools.read_logs, tools.page_oncall],
        sub_agents=[remediation_agent],
    )


def build_app(
    model: Any, *, alert: dict[str, Any] | None = None
) -> tuple[App, authority.OnCallAuthority, InvocationPlugin, FleetGateway]:
    """Wire the holder plugin and the fleet gateway for one alert."""
    alert = alert_mod.ALERT if alert is None else alert
    team = authority.provision()
    gateway = FleetGateway(trusted_roots=team.trusted_roots)
    plugin = InvocationPlugin(team, alert)
    tools.bind(gateway, plugin.proofs)
    application = App(
        name=APP_NAME,
        root_agent=build_root_agent(model),
        plugins=[plugin],
    )
    return application, team, plugin, gateway


# The module-level objects the ADK CLI looks for. `adk run` and `adk web`
# check for `app` first and fall back to `root_agent`; exposing the App
# is what carries the plugin into a CLI-driven run.
#
# They are built lazily (PEP 562). Only a CLI-driven run touches these
# names, and that run requires MODEL_NAME (see `.env.example`); there is
# deliberately no in-code default. `demo.py` and the tests call
# `build_app()` with their own model, so importing this module has no
# side effects for them.
#
# A CLI run builds once, on first access, so every session `adk web`
# serves shares one standing role and one set of keys. Tickets are still
# granted per session at hand-off, and the ticket's ten minutes start
# then. Fine for trying the recipe out; call `build_app()` per alert
# where that matters.
_cli_singletons: dict[str, Any] = {}


def __getattr__(name: str) -> Any:
    if name not in (
        "app",
        "root_agent",
        "team_authority",
        "invocation_plugin",
        "fleet_gateway",
    ):
        raise AttributeError(name)
    if not _cli_singletons:
        model = os.getenv("MODEL_NAME")
        if not model:
            raise RuntimeError(
                "MODEL_NAME is not set - a CLI-driven run (`adk run app`, "
                "`adk web`) needs it; see .env.example. The offline demo "
                "(`python demo.py`) does not use it."
            )
        application, team, plugin, gateway = build_app(model)
        _cli_singletons.update(
            app=application,
            root_agent=application.root_agent,
            team_authority=team,
            invocation_plugin=plugin,
            fleet_gateway=gateway,
        )
    return _cli_singletons[name]
