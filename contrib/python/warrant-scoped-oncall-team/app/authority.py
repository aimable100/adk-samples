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

"""Who holds what, written down as signed warrants.

Two warrants, one chain:

1. The ROLE warrant. The platform key mints it to the coordinator's
   key. It says what the on-call role may do at all: read any logs,
   scale or restart `web-*` services up to ten replicas, page, and hand
   an alert to the remediation agent.

2. The TICKET warrant. When an alert arrives the coordinator narrows
   its role into a ticket for the remediation agent: this one service,
   at most four replicas, ten minutes, bound to the remediation agent's
   OWN key. The library refuses the grant if it widens anything the
   role holds (`MonotonicityError`).

The values the ticket is narrowed to come from the alert record, never
from model output. Each agent signs its tool calls with its own key,
so a ticket copied out of one agent is useless to another.

Every argument a tool accepts must be named in the capability that
covers it. An argument with no constraint is refused as an unknown
field, so a free-text argument gets `Wildcard()` explicitly.
"""

from dataclasses import dataclass

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

ROLE_TTL_SECONDS = 3600  # one on-call shift segment
ROLE_MAX_REPLICAS = 10.0
ROLE_SERVICE_PATTERN = "web-*"

TICKET_TTL_SECONDS = 600  # ten minutes: long enough to act, not to linger
TICKET_MAX_REPLICAS = 4.0


def mint_role(platform_key: SigningKey, coordinator_key: SigningKey) -> Warrant:
    """The on-call role, minted by the platform to the coordinator."""
    return (
        Warrant.mint_builder()
        .capability("read_logs", service=Pattern("*"))
        .capability(
            "scale_service",
            service=Pattern(ROLE_SERVICE_PATTERN),
            replicas=Range.max_value(ROLE_MAX_REPLICAS),
        )
        .capability("restart_service", service=Pattern(ROLE_SERVICE_PATTERN))
        .capability("page_oncall", reason=Wildcard())
        .capability(
            "transfer_to_agent", agent_name=OneOf([REMEDIATION_AGENT_NAME])
        )
        .holder(coordinator_key.public_key)
        .ttl(ROLE_TTL_SECONDS)
        .mint(platform_key)
    )


def narrow_ticket(
    role: Warrant,
    coordinator_key: SigningKey,
    remediation_key: SigningKey,
    service: str,
) -> Warrant:
    """The coordinator narrows its role into a ticket for one service.

    Raises `tenuo.exceptions.MonotonicityError` if the ticket would hold
    anything the role does not: an extra tool, a wider pattern, a
    higher ceiling, a longer life.
    """
    return (
        role.grant_builder()
        .capability("read_logs", service=Exact(service))
        .capability(
            "scale_service",
            service=Exact(service),
            replicas=Range.max_value(TICKET_MAX_REPLICAS),
        )
        .holder(remediation_key.public_key)
        .ttl(TICKET_TTL_SECONDS)
        .grant(coordinator_key)
    )


@dataclass(frozen=True)
class TeamAuthority:
    """Everything the plugin needs to check a call from either agent.

    `chains` maps an agent name to its full warrant chain, root first.
    `keys` maps an agent name to the key that chain is bound to. The
    platform key is deliberately not here: once the role is minted it
    is not needed to run, only its public half is, as a trusted root.
    """

    trusted_roots: list
    keys: dict[str, SigningKey]
    chains: dict[str, list[Warrant]]

    def chain_for(self, agent_name: str) -> list[Warrant]:
        return list(self.chains[agent_name])

    def key_for(self, agent_name: str) -> SigningKey:
        return self.keys[agent_name]


def issue(service: str) -> TeamAuthority:
    """Mint the role, narrow the ticket, and hand back the result.

    Keys are generated here for a self-contained run. In a deployment
    the platform key is held by whatever provisions agents, and each
    agent process holds only its own key.
    """
    platform_key = SigningKey.generate()
    coordinator_key = SigningKey.generate()
    remediation_key = SigningKey.generate()

    role = mint_role(platform_key, coordinator_key)
    ticket = narrow_ticket(role, coordinator_key, remediation_key, service)

    return TeamAuthority(
        trusted_roots=[platform_key.public_key],
        keys={
            COORDINATOR_AGENT_NAME: coordinator_key,
            REMEDIATION_AGENT_NAME: remediation_key,
        },
        chains={
            COORDINATOR_AGENT_NAME: [role],
            REMEDIATION_AGENT_NAME: [role, ticket],
        },
    )
