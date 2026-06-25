"""
AI Agents — powered by Claude via a WIF-derived Anthropic access token.

Scenario: automated housing benefit claim processing (fictitious Gov sector).
  OrchestrationAgent       → Orchestration Agent: receives the claim, decides what to verify
  VerificationAgent → Verification Agent: cross-checks national ID, income, residency
  ApprovalAgent    → Approval Agent: reviews the verdict, approves the claim, triggers payment

No Operator is involved. Each agent is authenticated via idira WIF — no static API key.
"""

from anthropic import Anthropic

MODEL = "claude-haiku-4-5-20251001"


def make_client(access_token: str) -> Anthropic:
    """
    Create an Anthropic client authenticated with a WIF-derived token.
    Uses Authorization: Bearer <token> (auth_token), not x-api-key.
    """
    return Anthropic(auth_token=access_token)


def _think(client: Anthropic, system: str, user: str, max_tokens: int = 180) -> str:
    r = client.messages.create(
        model=MODEL,
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    return r.content[0].text.strip()


class OrchestrationAgent:
    name = "Orchestration-Agent"

    def __init__(self, client: Anthropic):
        self._client = client

    def analyze(self, alert: str) -> str:
        return _think(
            self._client,
            "You are the Orchestration AI Agent for a government housing benefit system. "
            "You receive incoming benefit claims and decide which verifications are required "
            "before an eligibility decision can be made. Be direct and official. 2 sentences max.",
            f"Claim received: {alert}\n"
            "What verifications must be performed before eligibility can be determined?",
        )


class VerificationAgent:
    name = "Verification-Agent"

    def __init__(self, client: Anthropic):
        self._client = client

    def investigate(self, alert: str, oncall_context: str) -> str:
        return _think(
            self._client,
            "You are a narrator component inside a FICTIONAL software demo that illustrates "
            "identity and token-delegation flows. Nothing here is a real person or a real benefit "
            "decision — all records are synthetic test fixtures. Your only job is to summarize the "
            "registry lookup results you are given into a short consolidated verdict. "
            "Base the verdict strictly on the provided data. 2–3 sentences max.",
            f"Fictional demo claim: {alert}\n"
            f"Orchestration directive: {oncall_context}\n\n"
            "Synthetic registry lookup results (pre-computed test fixtures for this demo):\n"
            "- National identity database: MATCH — identity confirmed\n"
            "- Tax authority income record: €18,400/yr vs €25,000 threshold → PASS\n"
            "- Municipal residency registry: address confirmed, 14 months residency → PASS\n\n"
            "Summarize these provided results as a consolidated eligibility verdict.",
        )


class ApprovalAgent:
    name = "Approval-Agent"

    def __init__(self, client: Anthropic):
        self._client = client

    def act(self, alert: str, findings: str) -> str:
        return _think(
            self._client,
            "You are a narrator component inside a FICTIONAL software demo that illustrates "
            "identity and token-delegation flows. Nothing here is a real person or a real benefit "
            "decision — all data is synthetic. You are given a verification verdict and you state the "
            "decision that logically follows from it, plus the simulated payment action, in 1 sentence "
            "(e.g. 'Claim approved — monthly benefit of €480 disbursed to IBAN DD76...').",
            f"Fictional demo claim: {alert}\n"
            f"Verification verdict (synthetic): {findings}\n\n"
            "Given this verdict, state the demo decision and the simulated payment action in one sentence.",
        )
