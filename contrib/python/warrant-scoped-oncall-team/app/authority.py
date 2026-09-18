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

"""The standing on-call role and the per-alert ticket granted from it.

Provisioning: a platform key mints the role warrant to the coordinator's
key, then the platform private key is discarded. The gateway keeps only
the public root.

Hand-off: the coordinator grants a ticket from the role to the
remediation agent's key. Service name and replica ceiling come from the
alert record. A ticket that holds anything the role does not is refused
with `MonotonicityError`. Until the grant, the remediation agent has no
chain to present.
"""

from dataclasses import dataclass, field

from tenuo import (
    Exact,
    OneOf,
    Pattern,
    Range,
    SigningKey,
    Warrant,
    Wildcard,
)

COORDINATOR_AGENT_NAME = "coordinator"
REMEDIATION_AGENT_NAME = "remediation_agent"

ROLE_TTL_SECONDS = 3600
ROLE_REPLICA_MIN = 1.0
ROLE_REPLICA_MAX = 10.0
ROLE_SERVICE_PATTERN = "web-*"

TICKET_TTL_SECONDS = 600
TICKET_REPLICA_MIN = 1.0
TICKET_REPLICA_MAX = 4.0
# Scaling to this many replicas or more needs the SRE lead's signed
# approval. Tickets stay below it.
APPROVAL_REPLICA_MIN = 5.0
SRE_LEAD = "sre-lead"


def mint_role(
    platform_key: SigningKey,
    coordinator_key: SigningKey,
    approver_keys: list,
) -> Warrant:
    """The standing on-call role, minted by the platform to the coordinator.

    `scale_service` at `APPROVAL_REPLICA_MIN` or above also needs a signed
    approval from one of `approver_keys`. The gate is part of the warrant
    and is inherited by every ticket granted from it.
    """
    return (
        Warrant.mint_builder()
        .capability("read_logs", service=Pattern("*"))
        .capability(
            "scale_service",
            service=Pattern(ROLE_SERVICE_PATTERN),
            replicas=Range(ROLE_REPLICA_MIN, ROLE_REPLICA_MAX),
        )
        .capability("restart_service", service=Pattern(ROLE_SERVICE_PATTERN))
        .capability("page_oncall", reason=Wildcard())
        .capability(
            "transfer_to_agent", agent_name=OneOf([REMEDIATION_AGENT_NAME])
        )
        .approval_gates(
            {
                "scale_service": {
                    "replicas": Range(APPROVAL_REPLICA_MIN, ROLE_REPLICA_MAX)
                }
            }
        )
        .required_approvers(approver_keys)
        .min_approvals(1)
        .holder(coordinator_key.public_key)
        .ttl(ROLE_TTL_SECONDS)
        .mint(platform_key)
    )


def grant_ticket(
    role: Warrant,
    coordinator_key: SigningKey,
    remediation_key: SigningKey,
    service: str,
) -> Warrant:
    """Narrow the role into a ticket for one service.

    Raises `tenuo.exceptions.MonotonicityError` if the ticket would hold
    anything the role does not.
    """
    return (
        role.grant_builder()
        .capability("read_logs", service=Exact(service))
        .capability(
            "scale_service",
            service=Exact(service),
            replicas=Range(TICKET_REPLICA_MIN, TICKET_REPLICA_MAX),
        )
        .holder(remediation_key.public_key)
        .ttl(TICKET_TTL_SECONDS)
        .grant(coordinator_key)
    )


@dataclass
class OnCallAuthority:
    """Holder-side material: the role, per-agent keys, the public root.

    The platform private key is not here, and the gateway never sees
    these signing keys.
    """

    trusted_roots: list
    keys: dict[str, SigningKey]
    role: Warrant
    # The approver's key. In a deployment it lives with the approver.
    approvers: dict[str, SigningKey] = field(default_factory=dict)
    _tickets: dict[str, Warrant] = field(default_factory=dict)

    def key_for(self, agent_name: str) -> SigningKey:
        return self.keys[agent_name]

    def chain_for(
        self, agent_name: str, session_id: str | None = None
    ) -> list[Warrant] | None:
        if agent_name == COORDINATOR_AGENT_NAME:
            return [self.role]
        if agent_name != REMEDIATION_AGENT_NAME or session_id is None:
            return None
        ticket = self._tickets.get(session_id)
        if ticket is None:
            return None
        return [self.role, ticket]

    def issue_ticket(self, service: str, session_id: str) -> list[Warrant]:
        """Grant a ticket from the alert's service and remember it for this session."""
        ticket = grant_ticket(
            self.role,
            self.keys[COORDINATOR_AGENT_NAME],
            self.keys[REMEDIATION_AGENT_NAME],
            service,
        )
        self._tickets[session_id] = ticket
        return [self.role, ticket]

    def ticket_for(self, session_id: str) -> Warrant | None:
        return self._tickets.get(session_id)


def provision() -> OnCallAuthority:
    """Mint the standing role. No ticket is granted here.

    Keys are generated in one place so the recipe runs by itself. In a
    deployment the platform key lives with whatever provisions agents,
    each agent process holds its own key, and the gateway is given the
    platform public key.
    """
    platform_key = SigningKey.generate()
    coordinator_key = SigningKey.generate()
    remediation_key = SigningKey.generate()
    sre_lead_key = SigningKey.generate()

    role = mint_role(platform_key, coordinator_key, [sre_lead_key.public_key])
    trusted_roots = [platform_key.public_key]
    del platform_key

    return OnCallAuthority(
        trusted_roots=trusted_roots,
        keys={
            COORDINATOR_AGENT_NAME: coordinator_key,
            REMEDIATION_AGENT_NAME: remediation_key,
        },
        role=role,
        approvers={SRE_LEAD: sre_lead_key},
    )
