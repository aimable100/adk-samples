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

"""The recipe's claims, asserted. Offline: no API key, no network."""

import time
from types import SimpleNamespace

import pytest
from tenuo import (
    ApprovalRequest,
    Authorizer,
    Exact,
    Pattern,
    Range,
    SigningKey,
    Warrant,
    approval_requirement,
    decode_warrant_stack_base64,
    encode_warrant_stack,
    sign_approval,
)
from tenuo.exceptions import (
    ApprovalGateTriggered,
    DelegationAuthorityError,
    DepthExceeded,
    ExpiredError,
    InvalidApproval,
    MonotonicityError,
    SignatureInvalid,
    UntrustedRoot,
    ValidationError,
)
from tenuo_core import verify_receipt

import demo
from app import alert, authority, tools
from app.agent import REMEDIATION_AGENT_NAME, ROOT_AGENT_NAME, build_app
from app.gateway import DENIED, FleetGateway, ProofRegistry
from app.plugin import InvocationPlugin

SERVICE = alert.ALERT["service"]


@pytest.fixture(scope="module")
def run():
    events, team, plugin, gateway = demo.run_offline()
    return demo.tool_calls(events), team, plugin, gateway


@pytest.fixture
def team():
    return authority.provision()


def _call(calls, tool, **args):
    matches = [
        c
        for c in calls
        if c.tool == tool and all(c.args.get(k) == v for k, v in args.items())
    ]
    assert len(matches) == 1, matches
    return matches[0]


def test_no_ticket_exists_until_handoff(team):
    assert team.ticket_for("session-1") is None
    assert team.chain_for(REMEDIATION_AGENT_NAME, "session-1") is None


def test_ticket_is_granted_from_the_alert_service_not_the_model(team):
    chain = team.issue_ticket(SERVICE, "session-1")
    ticket = chain[-1]
    assert str(ticket.holder_key) == str(
        team.key_for(REMEDIATION_AGENT_NAME).public_key
    )
    assert str(ticket.holder_key) != str(
        team.key_for(ROOT_AGENT_NAME).public_key
    )
    assert ticket.ttl_seconds() < team.role.ttl_seconds()
    assert set(ticket.tools) < set(team.role.tools)
    assert "restart_service" not in ticket.tools
    assert "transfer_to_agent" not in ticket.tools
    assert "scale_service" in ticket.tools
    assert "restart_service" not in team.ticket_for("session-1").tools


def test_platform_private_key_is_not_retained(team):
    assert not hasattr(team, "platform_key")
    gateway = FleetGateway(trusted_roots=team.trusted_roots)
    assert gateway.trusted_roots == team.trusted_roots
    assert not hasattr(gateway, "keys")


def test_handoff_and_in_ticket_calls_reach_the_fleet(run):
    calls, _team, plugin, gateway = run
    transfer = _call(calls, "transfer_to_agent")
    assert transfer.agent == ROOT_AGENT_NAME
    assert not transfer.denied
    assert plugin.handoffs and plugin.handoffs[0].allowed
    assert gateway.fleet[SERVICE] == 3
    allowed = [d for d in gateway.decisions if d.allowed]
    assert {d.tool for d in allowed} >= {"read_logs", "scale_service"}


def test_injected_calls_are_denied_and_the_fleet_is_unchanged(run):
    calls, _team, _plugin, gateway = run
    over = _call(calls, "scale_service", service=SERVICE, replicas=50)
    other = _call(calls, "scale_service", service="db-primary")
    restart = _call(calls, "restart_service", service="web-payments")

    for call in (over, other, restart):
        assert call.agent == REMEDIATION_AGENT_NAME
        assert call.response["error"] == DENIED

    assert over.response["reason"] == "ConstraintViolation"
    assert "replicas" in over.response["detail"]
    assert other.response["reason"] == "ConstraintViolation"
    assert "service" in other.response["detail"]
    assert restart.response["reason"] == "ToolNotAuthorized"
    assert gateway.fleet["web-payments"] == 3
    assert gateway.fleet["db-primary"] == 1
    assert gateway.fleet[SERVICE] == 3


def test_gateway_refuses_a_tool_call_with_no_proof(team):
    gateway = FleetGateway(trusted_roots=team.trusted_roots)
    tools.bind(gateway, ProofRegistry())
    result = tools.scale_service(SERVICE, 3, tool_context=None)
    assert result["error"] == DENIED
    assert result["reason"] == "NoInvocation"
    assert gateway.fleet[SERVICE] == 2


def test_gateway_refuses_a_proof_of_different_arguments(team):
    gateway = FleetGateway(trusted_roots=team.trusted_roots)
    plugin = InvocationPlugin(team, alert.ALERT)
    chain = team.issue_ticket(SERVICE, "s")
    proof = plugin.sign(
        REMEDIATION_AGENT_NAME,
        "scale_service",
        {
            "service": SERVICE,
            "replicas": 3,
        },
        "s",
    )
    result = gateway.invoke(
        "scale_service",
        {"service": SERVICE, "replicas": 50},
        proof,
    )
    assert result["error"] == DENIED
    assert result["reason"] == "InvocationMismatch"
    assert gateway.fleet[SERVICE] == 2
    assert chain[-1] is team.ticket_for("s")


def test_remediation_cannot_hand_the_alert_on(team):
    plugin = InvocationPlugin(team, alert.ALERT)
    team.issue_ticket(SERVICE, "s")
    refusal = plugin._handoff(
        REMEDIATION_AGENT_NAME,
        {"agent_name": ROOT_AGENT_NAME},
        SimpleNamespace(state={}),
        "s",
    )
    assert refusal is not None
    assert refusal["reason"] == "ToolNotAuthorized"
    # A refused transfer must not mint a second ticket.
    assert "restart_service" not in team.ticket_for("s").tools


def test_missing_plugin_is_a_gateway_deny_not_a_silent_allow(team):
    gateway = FleetGateway(trusted_roots=team.trusted_roots)
    tools.bind(gateway, ProofRegistry())
    ctx = SimpleNamespace(state={}, function_call_id="call-1")
    result = tools.restart_service("web-payments", tool_context=ctx)
    assert result["reason"] == "NoInvocation"
    assert gateway.fleet["web-payments"] == 3


def test_a_proof_is_single_use_and_never_in_session_state(team):
    gateway = FleetGateway(trusted_roots=team.trusted_roots)
    plugin = InvocationPlugin(team, alert.ALERT)
    tools.bind(gateway, plugin.proofs)
    team.issue_ticket(SERVICE, "s")
    proof = plugin.sign(
        REMEDIATION_AGENT_NAME,
        "scale_service",
        {"service": SERVICE, "replicas": 3},
        "s",
    )
    plugin.proofs.put("call-7", proof)
    ctx = SimpleNamespace(state={}, function_call_id="call-7")
    first = tools.scale_service(SERVICE, 3, tool_context=ctx)
    assert "error" not in first and gateway.fleet[SERVICE] == 3
    # Same call id again: the proof was taken once and is gone.
    second = tools.scale_service(SERVICE, 3, tool_context=ctx)
    assert second["reason"] == "NoInvocation"
    assert ctx.state == {}


def test_a_call_with_no_session_gets_no_ticket(team):
    plugin = InvocationPlugin(team, alert.ALERT)
    refusal = plugin._handoff(
        ROOT_AGENT_NAME,
        {"agent_name": REMEDIATION_AGENT_NAME},
        SimpleNamespace(state={}),
        None,
    )
    assert refusal is not None and refusal["reason"] == "NoWarrant"
    assert (
        plugin.sign(
            REMEDIATION_AGENT_NAME, "read_logs", {"service": SERVICE}, None
        )
        is None
    )


def test_leaked_ticket_replayed_with_another_key_fails(team):
    chain = team.issue_ticket(SERVICE, "s")
    leaked = decode_warrant_stack_base64(encode_warrant_stack(chain))
    stranger = SigningKey.generate()
    args = {"service": SERVICE}
    signature = leaked[-1].sign(stranger, "read_logs", args, int(time.time()))

    with pytest.raises(SignatureInvalid):
        Authorizer(trusted_roots=team.trusted_roots).check_chain(
            leaked, "read_logs", args, signature
        )


def test_ticket_alone_does_not_verify_without_its_chain(team):
    chain = team.issue_ticket(SERVICE, "s")
    key = team.key_for(REMEDIATION_AGENT_NAME)
    args = {"service": SERVICE}
    signature = chain[-1].sign(key, "read_logs", args, int(time.time()))

    with pytest.raises(UntrustedRoot):
        Authorizer(trusted_roots=team.trusted_roots).check_chain(
            [chain[-1]], "read_logs", args, signature
        )


def test_a_ticket_wider_than_the_role_is_refused_at_grant_time(team):
    coordinator = team.key_for(ROOT_AGENT_NAME)
    remediation = team.key_for(REMEDIATION_AGENT_NAME)
    with pytest.raises(MonotonicityError) as info:
        (
            team.role.grant_builder()
            .capability(
                "scale_service",
                service=Exact(SERVICE),
                replicas=Range(1.0, 50.0),
            )
            .holder(remediation.public_key)
            .ttl(authority.TICKET_TTL_SECONDS)
            .grant(coordinator)
        )
    assert info.value.details["bound"] == "max"
    with pytest.raises(MonotonicityError):
        (
            team.role.grant_builder()
            .capability("delete_service", service=Exact(SERVICE))
            .holder(remediation.public_key)
            .ttl(authority.TICKET_TTL_SECONDS)
            .grant(coordinator)
        )


def test_the_ticket_is_terminal_and_names_its_intent(team):
    ticket = team.issue_ticket(
        SERVICE, "s", intent="remediate ALR-2291 on web-checkout"
    )[-1]
    assert ticket.is_terminal()
    receipt = ticket.delegation_receipt
    assert receipt.intent == "remediate ALR-2291 on web-checkout"
    assert receipt.parent_warrant_id == team.role.id
    assert receipt.child_warrant_id == ticket.id
    key = team.key_for(REMEDIATION_AGENT_NAME)
    with pytest.raises(DepthExceeded):
        (
            ticket.grant_builder()
            .capability(
                "scale_service",
                service=Exact(SERVICE),
                replicas=Range(1.0, 2.0),
            )
            .holder(SigningKey.generate().public_key)
            .ttl(60)
            .grant(key)
        )


def test_a_wider_pattern_or_a_non_holder_grant_is_refused(team):
    coordinator = team.key_for(ROOT_AGENT_NAME)
    remediation = team.key_for(REMEDIATION_AGENT_NAME)
    with pytest.raises(MonotonicityError):
        (
            team.role.grant_builder()
            .capability(
                "scale_service", service=Pattern("*"), replicas=Range(1.0, 4.0)
            )
            .holder(remediation.public_key)
            .ttl(60)
            .grant(coordinator)
        )
    with pytest.raises(DelegationAuthorityError):
        (
            team.role.grant_builder()
            .capability(
                "scale_service",
                service=Exact(SERVICE),
                replicas=Range(1.0, 4.0),
            )
            .holder(remediation.public_key)
            .ttl(60)
            .grant(SigningKey.generate())
        )


def test_a_longer_ttl_is_clamped_to_the_role(team):
    ticket = (
        team.role.grant_builder()
        .capability("read_logs", service=Exact(SERVICE))
        .holder(team.key_for(REMEDIATION_AGENT_NAME).public_key)
        .ttl(authority.ROLE_TTL_SECONDS * 2)
        .grant(team.key_for(ROOT_AGENT_NAME))
    )
    assert ticket.ttl_seconds() <= team.role.ttl_seconds()


def test_an_expired_ticket_is_refused(team):
    key = team.key_for(REMEDIATION_AGENT_NAME)
    short = (
        team.role.grant_builder()
        .capability("read_logs", service=Exact(SERVICE))
        .holder(key.public_key)
        .ttl(1)
        .grant(team.key_for(ROOT_AGENT_NAME))
    )
    time.sleep(2)
    args = {"service": SERVICE}
    with pytest.raises(ExpiredError):
        Authorizer(trusted_roots=team.trusted_roots).check_chain(
            [team.role, short],
            "read_logs",
            args,
            short.sign(key, "read_logs", args, int(time.time())),
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


def test_every_gateway_decision_has_a_verifiable_receipt(run):
    _calls, _team, _plugin, gateway = run
    assert len(gateway.receipts) == len(gateway.decisions)
    key_hex = bytes(gateway.receipt_public_key.to_bytes()).hex()
    outcomes = []
    for wire, decision in zip(gateway.receipts, gateway.decisions, strict=True):
        payload = verify_receipt(wire)
        signer = payload.signer_key
        assert (
            signer if isinstance(signer, str) else bytes(signer).hex()
        ) == key_hex
        outcomes.append(payload.outcome)
        assert (payload.outcome == "allow") == decision.allowed
    assert "deny" in outcomes and "allow" in outcomes


def test_a_tampered_receipt_does_not_verify(run):
    _calls, _team, _plugin, gateway = run
    with pytest.raises(ValidationError):
        verify_receipt(gateway.receipts[0][:-8] + "AAAAAAAA")


def test_ticket_calls_are_never_gated_and_role_calls_above_four_are(team):
    ticket = team.issue_ticket(SERVICE, "s")[-1]
    small = {"service": SERVICE, "replicas": 3}
    big = {"service": SERVICE, "replicas": 6}
    assert (
        approval_requirement(ticket, "scale_service", small).status
        == "not_gated"
    )
    assert (
        approval_requirement(team.role, "scale_service", small).status
        == "not_gated"
    )
    assert (
        approval_requirement(team.role, "scale_service", big).status
        == "required"
    )


def test_above_the_ticket_needs_the_named_approver(team):
    gateway = FleetGateway(trusted_roots=team.trusted_roots)
    plugin = InvocationPlugin(team, alert.ALERT)
    big = {"service": SERVICE, "replicas": 6}
    proof = plugin.sign(ROOT_AGENT_NAME, "scale_service", big, None)
    refused = gateway.invoke("scale_service", big, proof)
    assert refused["reason"] == "ApprovalGateTriggered"
    assert gateway.fleet[SERVICE] == 2

    authorizer = Authorizer(trusted_roots=team.trusted_roots)
    with pytest.raises(ApprovalGateTriggered) as info:
        authorizer.check_chain(
            [team.role], "scale_service", big, proof.signature
        )
    request = ApprovalRequest(
        tool="scale_service",
        arguments=big,
        warrant_id=team.role.id,
        request_hash=bytes.fromhex(info.value.request_hash),
        required_approvers=[k.public_key for k in team.approvers.values()],
        min_approvals=info.value.min_approvals,
    )
    stranger = sign_approval(request, SigningKey.generate(), external_id="x")
    with pytest.raises(InvalidApproval):
        authorizer.check_chain(
            [team.role],
            "scale_service",
            big,
            proof.signature,
            approvals=[stranger],
        )
    lead = sign_approval(
        request,
        team.approvers[authority.SRE_LEAD],
        external_id=authority.SRE_LEAD,
    )
    proof = plugin.sign(ROOT_AGENT_NAME, "scale_service", big, None)
    done = gateway.invoke("scale_service", big, proof, approvals=[lead])
    assert done["replicas"] == 6 and gateway.fleet[SERVICE] == 6


def test_the_demo_exits_zero(capsys):
    assert demo.main([]) == 0
    assert "RESULT: OK" in capsys.readouterr().out


def test_build_app_does_not_grant_a_ticket():
    application, team, _plugin, _gateway = build_app("scripted-offline-model")
    assert application.root_agent is not None
    assert team.ticket_for("anything") is None
