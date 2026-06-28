"""
Security Token Service — RFC 8693 Token Exchange (agent-to-agent delegation)

Scenario: automated housing benefit claim processing (fictitious Gov sector).
Each agent-to-agent hop exchanges a short-lived, audience-locked JWT that carries
the full delegation chain in the `act` claim.

This runs on top of the Anthropic WIF token (which covers workload → Anthropic auth).
The two layers are complementary:
    WIF  →  benefit-processing workload proves its identity to Anthropic
    STS  →  agents prove their delegation chain to each other / to downstream Gov APIs
"""

import uuid
import jwt as pyjwt
from datetime import datetime, timedelta, timezone
from typing import Optional

STS_SECRET  = "rfc8693-demo-not-for-prod"   # In production: RSA/ECDSA key pair
TOKEN_TTL   = 300                            # 5-minute tokens


class SecurityTokenService:
    REGISTRY = {
        "Orchestration-Agent": {"allowed_targets": ["Verification-Agent"]},
        "Verification-Agent":  {"allowed_targets": ["Approval-Agent"]},
        "Approval-Agent":      {"allowed_targets": ["eligibility-api", "payment-api"]},
    }

    def __init__(self):
        self.exchange_log: list[dict] = []

    # ── Public API ────────────────────────────────────────────────────────────

    def mint_session_token(self, user_sub: str, first_agent: str) -> dict:
        """Issue the root token that anchors a human's intent to the first agent."""
        payload = self._build_payload(
            sub=user_sub,
            aud=first_agent,
            act=None,
            session_id=str(uuid.uuid4())[:8],
        )
        token = pyjwt.encode(payload, STS_SECRET, algorithm="HS256")
        self._log("initial_mint", issuer=user_sub, target=first_agent, payload=payload)
        return {"token": token, "payload": payload}

    def exchange(self, incoming_token: str, requesting_agent: str, target: str) -> Optional[dict]:
        """
        RFC 8693 Token Exchange.

        Steps:
          1. Validate incoming token (audience must match requesting agent)
          2. Registry policy check (is this agent allowed to call target?)
          3. Build nested `act` chain (delegation history grows with each hop)
          4. Mint new short-lived, audience-locked JWT for this hop only
        """
        try:
            incoming = pyjwt.decode(
                incoming_token, STS_SECRET,
                algorithms=["HS256"],
                audience=requesting_agent,
            )
        except pyjwt.ExpiredSignatureError:
            return self._deny("token expired", requesting_agent, target)
        except pyjwt.InvalidAudienceError:
            return self._deny("wrong audience", requesting_agent, target)

        entry = self.REGISTRY.get(requesting_agent)
        if not entry or target not in entry["allowed_targets"]:
            return self._deny("policy denied — target not in allowed_targets", requesting_agent, target)

        prior_act = incoming.get("act")
        new_act = {"sub": requesting_agent}
        if prior_act:
            new_act["act"] = prior_act

        payload = self._build_payload(
            sub=incoming["sub"],
            aud=target,
            act=new_act,
            session_id=incoming.get("session_id", "?"),
        )
        token = pyjwt.encode(payload, STS_SECRET, algorithm="HS256")
        self._log("exchange", issuer=requesting_agent, target=target, payload=payload)
        return {"token": token, "payload": payload}

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _build_payload(self, sub, aud, act, session_id) -> dict:
        now = datetime.now(timezone.utc)
        p = {
            "iss": "https://sts.internal",
            "sub": sub,
            "aud": aud,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=TOKEN_TTL)).timestamp()),
            "jti": str(uuid.uuid4())[:8],
            "session_id": session_id,
        }
        if act:
            p["act"] = act
        return p

    def _deny(self, reason: str, actor: str, target: str) -> None:
        self._log(f"DENIED ({reason})", issuer=actor, target=target, payload={})
        return None

    def _log(self, action: str, issuer: str, target: str, payload: dict):
        self.exchange_log.append({
            "ts":      datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "action":  action,
            "issuer":  issuer,
            "target":  target,
            "session": payload.get("session_id", ""),
        })


def flatten_act(act: Optional[dict]) -> str:
    """Turn the nested `act` claim into a readable left-to-right chain string."""
    if not act:
        return ""
    chain = []
    node = act
    while node:
        chain.append(node.get("sub", "?"))
        node = node.get("act")
    return " → ".join(reversed(chain))
