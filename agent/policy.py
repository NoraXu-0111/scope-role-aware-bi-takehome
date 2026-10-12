"""Explicit capabilities. Model output never supplies an identity or a role."""
from __future__ import annotations
from dataclasses import dataclass
from . import db

T0 = frozenset({"customer_id", "full_name", "region", "segment", "risk_score", "onboarded_at", "deleted_at"})
T1 = frozenset({"zip3", "birth_year", "income_band"})
T2 = frozenset({"zip_code", "dob"})
T3 = frozenset({"annual_income_usd"})
T4 = frozenset({"national_id", "email", "phone"})
T5 = frozenset({"race", "ethnicity", "sex"})
CUSTOMER_COLUMNS = T0 | T1 | T2 | T3 | T4 | T5
VERSION = "2026-10-10-v1"

class AccessDenied(Exception):
    def __init__(self, reason: str, code: str = "access_denied"):
        super().__init__(reason)
        self.code = code

@dataclass(frozen=True)
class RolePolicy:
    customer_columns: frozenset[str]
    datasets: frozenset[str]
    own_region: bool = False
    active_only: bool = True
    aggregate_only: bool = False

BUSINESS = frozenset({"customers", "transactions", "alerts"})
POLICIES = {
    "analyst": RolePolicy(T0 | T1, BUSINESS, own_region=True),
    "reviewer": RolePolicy(T0 | T1 | T2 | T3, BUSINESS | {"case_notes"}, own_region=True),
    "compliance": RolePolicy(T0 | T1 | T2 | T3 | T4, BUSINESS | {"case_notes"}, active_only=False),
    "fair_lending": RolePolicy(frozenset({"region", "segment"}) | T1 | T3 | T5, BUSINESS, aggregate_only=True),
    "admin": RolePolicy(frozenset(), frozenset({"users"})),
}

@dataclass(frozen=True)
class AccessContext:
    user_id: str
    full_name: str
    role: str
    region: str | None
    conversation_id: str
    policy: RolePolicy

    @property
    def fingerprint(self) -> tuple:
        return (self.user_id, self.role, self.region, VERSION)

    def public_scope(self) -> dict:
        return {"region": self.region if self.policy.own_region else "all",
                "customers": "active" if self.policy.active_only else "active_or_offboarded",
                "aggregate_only": self.policy.aggregate_only,
                "datasets": sorted(self.policy.datasets), "policy_version": VERSION}

def resolve(user_id: str, conversation_id: str = "") -> AccessContext:
    user = db.get_user(user_id)
    policy = POLICIES.get(user["role"])
    if policy is None or (policy.own_region and user["region"] not in {"WEST", "EAST", "CENTRAL"}):
        raise AccessDenied("This identity has no valid access policy.", "invalid_identity")
    return AccessContext(**user, conversation_id=conversation_id, policy=policy)
