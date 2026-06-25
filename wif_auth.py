"""
WIF Authentication: Idira → Anthropic API

Implements Anthropic Workload Identity Federation (WIF) using Idira
as the OIDC provider. No static API keys — the workload authenticates with a
short-lived JWT issued by idira, then exchanges it for an Anthropic access token.

Flow:
    Workload → idira (client credentials) → OIDC JWT
    JWT → Anthropic /v1/oauth/token (RFC 7523 jwt-bearer) → sk-ant-oat01-... token
"""

import os
import requests
import jwt as pyjwt
from dataclasses import dataclass, field
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
#  Configuration
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Config:
    # Idira
    idira_tenant_url: str
    idira_client_id: str
    idira_client_secret: str
    idira_app_id: str
    idira_scope: str = "openid"

    # Anthropic WIF
    organization_id: str = ""
    service_account_id: str = ""
    federation_rule_id: str = ""
    workspace_id: str = ""

    @classmethod
    def from_env(cls) -> "Config":
        required = {
            "idira_TENANT_URL":           "Your Idira tenant URL",
            "idira_CLIENT_ID":            "OAuth2 app client ID in idira",
            "idira_CLIENT_SECRET":        "OAuth2 app client secret in idira",
            "idira_APP_ID":               "OAuth2 application name/ID in idira (used in token endpoint URL)",
            "ANTHROPIC_ORGANIZATION_ID":     "Your Anthropic organization UUID (Console → Settings → Organization)",
            "ANTHROPIC_SERVICE_ACCOUNT_ID":  "Service account ID, starts with svac_",
            "ANTHROPIC_FEDERATION_RULE_ID":  "Federation rule ID, starts with fdrl_",
            "ANTHROPIC_WORKSPACE_ID":        "Workspace ID, starts with wrkspc_",
        }
        missing = {k: v for k, v in required.items() if not os.environ.get(k)}
        if missing:
            lines = "\n".join(f"  {k}  — {desc}" for k, desc in missing.items())
            raise EnvironmentError(
                f"Missing required environment variables:\n{lines}\n\n"
                "Copy .env.example to .env and fill in the values."
            )

        return cls(
            idira_tenant_url=os.environ["idira_TENANT_URL"].rstrip("/"),
            idira_client_id=os.environ["idira_CLIENT_ID"],
            idira_client_secret=os.environ["idira_CLIENT_SECRET"],
            idira_app_id=os.environ["idira_APP_ID"],
            idira_scope=os.environ.get("idira_SCOPE", "openid"),
            organization_id=os.environ["ANTHROPIC_ORGANIZATION_ID"],
            service_account_id=os.environ["ANTHROPIC_SERVICE_ACCOUNT_ID"],
            federation_rule_id=os.environ["ANTHROPIC_FEDERATION_RULE_ID"],
            workspace_id=os.environ["ANTHROPIC_WORKSPACE_ID"],
        )


# ─────────────────────────────────────────────────────────────────────────────
#  Token data classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class idiraToken:
    raw: str       # The raw JWT string (sent to Anthropic WIF endpoint)
    claims: dict   # Decoded payload (no signature verification — Anthropic does that)

    @property
    def subject(self) -> str:
        return self.claims.get("sub", "unknown")

    @property
    def issuer(self) -> str:
        return self.claims.get("iss", "unknown")

    @property
    def audience(self) -> str:
        aud = self.claims.get("aud", "")
        return ", ".join(aud) if isinstance(aud, list) else str(aud)

    @property
    def expires_at(self) -> int:
        return self.claims.get("exp", 0)

    def display_claims(self) -> dict:
        """Claims to show in the terminal (excludes iat/nbf for brevity)."""
        return {
            k: v for k, v in self.claims.items()
            if k not in ("iat", "nbf")
        }


@dataclass
class AnthropicWIFToken:
    access_token: str   # sk-ant-oat01-... short-lived federated token
    expires_in: int     # seconds until expiry (default 3600)
    scope: str
    token_type: str

    @property
    def masked(self) -> str:
        """Show only the prefix — never log the full token."""
        parts = self.access_token.split("-")
        prefix = "-".join(parts[:4]) if len(parts) >= 4 else self.access_token[:20]
        return f"{prefix}-...[redacted]"


# ─────────────────────────────────────────────────────────────────────────────
#  WIF Authenticator
# ─────────────────────────────────────────────────────────────────────────────

class WIFAuthenticator:
    """
    Performs the two-step WIF authentication:
        1. idira client credentials → OIDC JWT
        2. JWT → Anthropic short-lived access token (RFC 7523 jwt-bearer grant)
    """

    ANTHROPIC_TOKEN_ENDPOINT = "https://api.anthropic.com/v1/oauth/token"

    def __init__(self, config: Config):
        self.config = config

    # ── Step 1: idira ─────────────────────────────────────────────────────

    @property
    def idira_token_endpoint(self) -> str:
        """
        Idira token endpoint pattern:
            POST https://<tenant>/oauth2/token/<AppID>
        The AppID routes the request to the correct OAuth2 application.
        """
        return f"{self.config.idira_tenant_url}/oauth2/token/{self.config.idira_app_id}"

    def get_idira_jwt(self) -> idiraToken:
        """
        Exchange client credentials for a idira OIDC JWT.
        Uses HTTP Basic auth (client_id:client_secret) per RFC 6749 §2.3.1.
        """
        try:
            resp = requests.post(
                self.idira_token_endpoint,
                data={
                    "grant_type": "client_credentials",
                    "scope": self.config.idira_scope,
                },
                auth=(self.config.idira_client_id, self.config.idira_client_secret),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=15,
            )
            resp.raise_for_status()
        except requests.HTTPError as e:
            body = e.response.text if e.response is not None else "(no body)"
            raise RuntimeError(
                f"idira token request failed ({e.response.status_code if e.response else '?'}):\n"
                f"  Endpoint: {self.idira_token_endpoint}\n"
                f"  Response: {body}\n\n"
                "Check: correct App ID? Client ID/secret match? App allows client_credentials grant?"
            ) from e
        except requests.RequestException as e:
            raise RuntimeError(
                f"Cannot reach idira tenant: {e}\n"
                f"  URL: {self.idira_token_endpoint}"
            ) from e

        data = resp.json()

        # idira returns id_token (explicit identity JWT) when scope includes openid.
        # Fall back to access_token if id_token is absent (some app configurations omit it).
        raw_jwt = data.get("id_token") or data.get("access_token")
        if not raw_jwt:
            raise ValueError(
                f"idira response contains no JWT.\n"
                f"  Response keys: {list(data.keys())}\n"
                "Ensure the OAuth2 app has 'openid' scope and 'id_token' generation enabled."
            )

        # Decode without verification — Anthropic verifies the signature via JWKS
        claims = pyjwt.decode(raw_jwt, options={"verify_signature": False})
        return idiraToken(raw=raw_jwt, claims=claims)

    # ── Step 2: Anthropic WIF ─────────────────────────────────────────────────

    def exchange_for_anthropic_token(self, idira_jwt: str) -> AnthropicWIFToken:
        """
        Exchange the idira JWT for a short-lived Anthropic access token.
        Implements RFC 7523 JWT Bearer Grant as specified by Anthropic WIF.

        The resulting token (sk-ant-oat01-...) is used with
        Authorization: Bearer <token> on every Claude API call.
        """
        try:
            resp = requests.post(
                self.ANTHROPIC_TOKEN_ENDPOINT,
                json={
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": idira_jwt,
                    "federation_rule_id": self.config.federation_rule_id,
                    "organization_id": self.config.organization_id,
                    "service_account_id": self.config.service_account_id,
                    "workspace_id": self.config.workspace_id,
                },
                headers={"Content-Type": "application/json"},
                timeout=15,
            )
            resp.raise_for_status()
        except requests.HTTPError as e:
            body = e.response.text if e.response is not None else "(no body)"
            raise RuntimeError(
                f"Anthropic WIF token exchange failed ({e.response.status_code if e.response else '?'}):\n"
                f"  Response: {body}\n\n"
                "Check:\n"
                "  • federation_rule_id, organization_id, service_account_id, workspace_id are correct\n"
                "  • The federation issuer's iss URL matches the iss claim in your idira JWT\n"
                "  • The federation rule's match conditions match the JWT's sub/claims\n"
                "  • The service account is added to the workspace"
            ) from e

        data = resp.json()
        return AnthropicWIFToken(
            access_token=data["access_token"],
            expires_in=data.get("expires_in", 3600),
            scope=data.get("scope", ""),
            token_type=data.get("token_type", "Bearer"),
        )

    # ── Full flow ─────────────────────────────────────────────────────────────

    def authenticate(self) -> tuple[idiraToken, AnthropicWIFToken]:
        """
        Full WIF authentication flow.
        Returns both tokens so the caller can display them in the demo.
        """
        idira_token = self.get_idira_jwt()
        anthropic_token = self.exchange_for_anthropic_token(idira_token.raw)
        return idira_token, anthropic_token
