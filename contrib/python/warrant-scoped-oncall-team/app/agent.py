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

"""An on-call coordinator with a remediation sub-agent, warrant-scoped.

Two ordinary `LlmAgent`s and one plugin. The coordinator holds the
on-call role; the remediation agent holds a ticket narrowed from it for
the one service named in the alert. `WarrantChainPlugin` is registered
once on the `App` and checks every tool call in the tree, so neither
agent's prompt, tool list or model choice is a security control.
"""

import os
from typing import Any

from google.adk.agents.llm_agent import LlmAgent
from google.adk.apps.app import App

from . import authority, tools
from .authz import WarrantChainPlugin
from .prompt import COORDINATOR_PROMPT, REMEDIATION_PROMPT

APP_NAME = "warrant-scoped-oncall-team"
ROOT_AGENT_NAME = authority.COORDINATOR_AGENT_NAME
REMEDIATION_AGENT_NAME = authority.REMEDIATION_AGENT_NAME


def build_root_agent(model: Any) -> LlmAgent:
    """The agent tree. `model` is a model name or a `BaseLlm` instance,
    so the offline demo can pass a scripted model in its place."""
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
) -> tuple[App, authority.TeamAuthority, WarrantChainPlugin]:
    """An `App` with the plugin attached, plus the warrants and keys it
    checks against. The ticket is narrowed to `alert["service"]`."""
    alert = tools.ALERT if alert is None else alert
    team = authority.issue(alert["service"])
    plugin = WarrantChainPlugin(team)
    application = App(
        name=APP_NAME,
        root_agent=build_root_agent(model),
        plugins=[plugin],
    )
    require_plugin(application)
    return application, team, plugin


def require_plugin(application: App) -> None:
    """Refuse to run an App that lost its plugin.

    Inside `build_app` this cannot fail today; it is a tripwire so that
    an edit which drops the plugin becomes a startup failure rather than
    a silent downgrade to unchecked tool calls.
    """
    plugins = getattr(application, "plugins", None) or []
    if not any(isinstance(p, WarrantChainPlugin) for p in plugins):
        raise RuntimeError(
            "WarrantChainPlugin is not attached to this App - "
            "refusing to run unchecked"
        )


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
# serves shares one role warrant, one ticket and one set of keys, and
# the ticket's ten minutes start counting then. Fine for trying the
# recipe out; call `build_app()` per alert for anything more.
_cli_singletons: dict[str, Any] = {}


def __getattr__(name: str) -> Any:
    if name not in ("app", "root_agent", "team_authority", "warrant_plugin"):
        raise AttributeError(name)
    if not _cli_singletons:
        model = os.getenv("MODEL_NAME")
        if not model:
            raise RuntimeError(
                "MODEL_NAME is not set - a CLI-driven run (`adk run app`, "
                "`adk web`) needs it; see .env.example. The offline demo "
                "(`python demo.py`) does not use it."
            )
        application, team, plugin = build_app(model)
        _cli_singletons.update(
            app=application,
            root_agent=application.root_agent,
            team_authority=team,
            warrant_plugin=plugin,
        )
    return _cli_singletons[name]
