"""Ephemeral exact-action authorization leases for Agent Airlock."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import time
from typing import Any, Callable
import uuid


def _canonical_json(data: dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def arguments_digest(arguments: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(arguments).encode()).hexdigest()


@dataclass(frozen=True)
class AuthorityLease:
    lease_id: str
    principal: str
    tool: str
    arguments_hash: str
    issued_at: float
    expires_at: float
    max_uses: int
    token: str

    def unsigned_payload(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("token")
        return data


@dataclass(frozen=True)
class LeaseDecision:
    allowed: bool
    reason: str
    lease_id: str | None


class LeaseManager:
    """Issue and consume HMAC-bound, short-lived, replay-limited leases."""

    def __init__(
        self,
        *,
        secret: bytes,
        clock: Callable[[], float] = time.time,
    ):
        if len(secret) < 16:
            raise ValueError("Lease signing secret must be at least 16 bytes.")
        self._secret = secret
        self._clock = clock
        self._leases: dict[str, AuthorityLease] = {}
        self._uses: dict[str, int] = {}
        self._revoked: set[str] = set()

    def _sign(self, payload: dict[str, Any]) -> str:
        return hmac.new(
            self._secret,
            _canonical_json(payload).encode(),
            hashlib.sha256,
        ).hexdigest()

    def issue(
        self,
        *,
        principal: str,
        tool: str,
        arguments: dict[str, Any],
        ttl_seconds: float = 60.0,
        max_uses: int = 1,
    ) -> AuthorityLease:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive.")
        if max_uses < 1:
            raise ValueError("max_uses must be at least 1.")

        now = float(self._clock())
        base = {
            "lease_id": uuid.uuid4().hex,
            "principal": principal,
            "tool": tool,
            "arguments_hash": arguments_digest(arguments),
            "issued_at": now,
            "expires_at": now + float(ttl_seconds),
            "max_uses": max_uses,
        }
        lease = AuthorityLease(token=self._sign(base), **base)
        self._leases[lease.token] = lease
        self._uses[lease.lease_id] = 0
        return lease

    def revoke(self, token: str) -> None:
        lease = self._leases.get(token)
        if lease is not None:
            self._revoked.add(lease.lease_id)

    def consume(
        self,
        *,
        token: str | None,
        principal: str,
        tool: str,
        arguments: dict[str, Any],
    ) -> LeaseDecision:
        if not token:
            return LeaseDecision(False, "High-risk action requires an authority lease.", None)

        lease = self._leases.get(token)
        if lease is None:
            return LeaseDecision(False, "Unknown authority lease.", None)

        if not hmac.compare_digest(self._sign(lease.unsigned_payload()), token):
            return LeaseDecision(False, "Authority lease signature is invalid.", lease.lease_id)

        if lease.lease_id in self._revoked:
            return LeaseDecision(False, "Authority lease has been revoked.", lease.lease_id)

        if float(self._clock()) > lease.expires_at:
            return LeaseDecision(False, "Authority lease has expired.", lease.lease_id)

        if principal != lease.principal or tool != lease.tool:
            return LeaseDecision(
                False,
                "Authority lease is bound to a different principal or tool.",
                lease.lease_id,
            )

        if arguments_digest(arguments) != lease.arguments_hash:
            return LeaseDecision(
                False,
                "Authority lease does not match the exact action arguments.",
                lease.lease_id,
            )

        uses = self._uses.get(lease.lease_id, 0)
        if uses >= lease.max_uses:
            return LeaseDecision(
                False,
                "Authority lease replay/use limit exceeded.",
                lease.lease_id,
            )

        self._uses[lease.lease_id] = uses + 1
        return LeaseDecision(True, "Exact-action authority lease accepted.", lease.lease_id)
