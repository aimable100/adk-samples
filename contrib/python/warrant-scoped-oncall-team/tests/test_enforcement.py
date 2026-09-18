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

"""What the recipe claims, asserted. Offline: no API key, no network."""

import time

import pytest
from google.adk.apps.app import App
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

import demo
from app import authority, tools
from app.agent import (
    REMEDIATION_AGENT_NAME,
    ROOT_AGENT_NAME,
    build_root_agent,
    require_plugin,
)
from app.authz import DENIED, WarrantChainPlugin

SERVICE = tools.ALERT["service"]


@pytest.fixture(scope="module")
def run():
    events, team, plugin = demo.run_offline()
    return demo.tool_calls(events), team, plugin, list(tools.EXECUTED)


@pytest.fixture(scope="module")
def team():
    return authority.issue(SERVICE)


def _call(calls, tool, **args):
    matches = [
        c
        for c in calls
        if c.tool == tool and all(c.args.get(k) == v for k, v in args.items())
    ]
    assert len(matches) == 1, matches
    return matches[0]


# ---------------------------------------------------------------- the run


def test_the_hand_off_and_the_in_ticket_calls_go_through(run):
    calls, _team, _plugin, executed = run
    transfer = _call(calls, "transfer_to_agent")
    assert transfer.agent == ROOT_AGENT_NAME
    assert not transfer.denied
    assert ("read_logs", SERVICE) in executed
    assert ("scale_service", (SERVICE, 3)) in executed


def test_the_injected_calls_are_refused_before_their_bodies_run(run):
    calls, _team, _plugin, executed = run
    over = _call(calls, "scale_service", service=SERVICE, replicas=50)
    other = _call(calls, "scale_service", service="db-primary")
    restart = _call(calls, "restart_service", service="web-payments")

    for call in (over, other, restart):
        assert call.agent == REMEDIATION_AGENT_NAME
        assert call.response["error"] == DENIED
        assert call.response["agent"] == REMEDIATION_AGENT_NAME
        # The proof that this was not "run it, then report it": each
        # tool body appends to EXECUTED as its first statement.
        assert demo.executed_entry(call) not in executed

    assert over.response["reason"] == "ConstraintViolation"
    assert "replicas" in over.response["detail"]
    assert other.response["reason"] == "ConstraintViolation"
    assert "service" in other.response["detail"]
    assert restart.response["reason"] == "ToolNotAuthorized"


def test_every_decision_is_recorded_on_the_plugin(run):
    calls, _team, plugin, _executed = run
    assert len(plugin.decisions) == len(calls)
    assert [d.allowed for d in plugin.decisions] == [
        not c.denied for c in calls
    ]


# ------------------------------------------------------------ the chain


def test_the_ticket_is_narrower_than_the_role(team):
    role = team.chain_for(ROOT_AGENT_NAME)[-1]
    ticket = team.chain_for(REMEDIATION_AGENT_NAME)[-1]

    assert set(ticket.tools) < set(role.tools)
    assert "restart_service" not in ticket.tools
    assert "transfer_to_agent" not in ticket.tools
    assert ticket.ttl_seconds() <= authority.TICKET_TTL_SECONDS
    assert ticket.depth == role.depth + 1


def test_the_ticket_is_bound_to_the_remediation_agents_own_key(team):
    ticket = team.chain_for(REMEDIATION_AGENT_NAME)[-1]
    remediation_key = team.key_for(REMEDIATION_AGENT_NAME)
    coordinator_key = team.key_for(ROOT_AGENT_NAME)

    assert str(ticket.holder_key) == str(remediation_key.public_key)
    assert str(ticket.holder_key) != str(coordinator_key.public_key)


def test_the_remediation_agent_cannot_hand_the_alert_on(team):
    plugin = WarrantChainPlugin(team)
    refusal = plugin.authorize(
        REMEDIATION_AGENT_NAME,
        "transfer_to_agent",
        {"agent_name": ROOT_AGENT_NAME},
    )
    assert refusal is not None
    assert refusal["reason"] == "ToolNotAuthorized"


def test_an_agent_with_no_chain_is_refused(team):
    plugin = WarrantChainPlugin(team)
    refusal = plugin.authorize("stray_agent", "read_logs", {"service": SERVICE})
    assert refusal is not None
    assert refusal["reason"] == "NoWarrant"


def test_an_argument_the_ticket_does_not_name_is_refused(team):
    plugin = WarrantChainPlugin(team)
    refusal = plugin.authorize(
        REMEDIATION_AGENT_NAME,
        "read_logs",
        {"service": SERVICE, "tail": 500},
    )
    assert refusal is not None
    assert refusal["reason"] == "ConstraintViolation"
    assert "unknown field" in refusal["detail"]


# ------------------------------------------------------ the three extras


def test_a_leaked_ticket_replayed_with_another_key_fails(team):
    chain = team.chain_for(REMEDIATION_AGENT_NAME)
    leaked = decode_warrant_stack_base64(encode_warrant_stack(chain))
    stranger = SigningKey.generate()
    args = {"service": SERVICE}
    signature = leaked[-1].sign(stranger, "read_logs", args, int(time.time()))

    with pytest.raises(SignatureInvalid):
        Authorizer(trusted_roots=team.trusted_roots).check_chain(
            leaked, "read_logs", args, signature
        )


def test_the_ticket_alone_does_not_verify_without_its_chain(team):
    chain = team.chain_for(REMEDIATION_AGENT_NAME)
    key = team.key_for(REMEDIATION_AGENT_NAME)
    args = {"service": SERVICE}
    signature = chain[-1].sign(key, "read_logs", args, int(time.time()))

    with pytest.raises(UntrustedRoot):
        Authorizer(trusted_roots=team.trusted_roots).check_chain(
            [chain[-1]], "read_logs", args, signature
        )


def test_widening_the_ticket_is_refused_at_grant_time(team):
    ticket = team.chain_for(REMEDIATION_AGENT_NAME)[-1]
    key = team.key_for(REMEDIATION_AGENT_NAME)

    with pytest.raises(MonotonicityError) as info:
        (
            ticket.grant_builder()
            .capability(
                "scale_service",
                service=Exact(SERVICE),
                replicas=Range.max_value(50.0),
            )
            .holder(key.public_key)
            .ttl(authority.TICKET_TTL_SECONDS)
            .grant(key)
        )
    assert info.value.details["bound"] == "max"

    with pytest.raises(MonotonicityError):
        (
            ticket.grant_builder()
            .capability("restart_service", service=Exact(SERVICE))
            .holder(key.public_key)
            .ttl(authority.TICKET_TTL_SECONDS)
            .grant(key)
        )


def test_a_warrant_from_an_unknown_issuer_is_refused(team):
    key = team.key_for(REMEDIATION_AGENT_NAME)
    forged = (
        Warrant.mint_builder()
        .capability("restart_service", service=Pattern("*"))
        .holder(key.public_key)
        .ttl(60)
        .mint(SigningKey.generate())
    )
    args = {"service": SERVICE}
    signature = forged.sign(key, "restart_service", args, int(time.time()))

    with pytest.raises(UntrustedRoot):
        Authorizer(trusted_roots=team.trusted_roots).check_chain(
            [forged], "restart_service", args, signature
        )


# ------------------------------------------------------------ the wiring


def test_an_app_without_the_plugin_refuses_to_start():
    unchecked = App(
        name="unchecked",
        root_agent=build_root_agent("scripted-offline-model"),
    )

    with pytest.raises(RuntimeError, match="refusing to run unchecked"):
        require_plugin(unchecked)


def test_the_demo_exits_zero(capsys):
    assert demo.main([]) == 0
    assert "RESULT: OK" in capsys.readouterr().out
