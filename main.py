#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   Agentic AI Identity Security — v1 (OAuth)                                        ║
║   Workload Identity Federation (WIF) · Idira · No API Keys    ║
║   RFC 8693 Token Exchange · JWT Actor Chains · Zero Trust for AI Agents    ║
║   by Elmehdi Aabad — Identity Security                                       ║
╚══════════════════════════════════════════════════════════════════════════════╝

Scenario (fictitious — Gov sector):
  An applicant submits a housing benefit claim through a government portal.
  Three AI agents process the claim end-to-end. No Operator reviews the decision.

    Orchestration Agent  →  receives the claim, decides what to verify
    Verification Agent   →  checks national ID, cross-references income with the tax
                            authority, validates residency through municipal registries
    Approval Agent       →  reviews the consolidated eligibility verdict, approves the
                            claim, and triggers the benefit payment

  Because no human reviews the decision, the identity and accountability trail
  must be unambiguous and cryptographically verifiable at every step.

  Auth flow:
    1. Workload → idira (client credentials) → short-lived OIDC JWT
    2. JWT → Anthropic WIF endpoint (RFC 7523) → sk-ant-oat01-... access token
    3. Claude agents call the API using that federated token (RFC 8693 chain)

  The full identity chain:
    idira IdP
      └── Workload identity (benefit-processing service)
            └── Anthropic access token (WIF)
                  └── Orchestration Agent (STS hop 1)
                        └── Verification Agent (STS hop 2)
                              └── Approval Agent (STS hop 3)
"""

import os
import time
import json
from dotenv import load_dotenv

from wif_auth import Config, WIFAuthenticator
from agents import make_client, OrchestrationAgent, VerificationAgent, ApprovalAgent
from sts import SecurityTokenService, flatten_act
import ui

load_dotenv()


# ─────────────────────────────────────────────────────────────────────────────
#  Phase 0 — WIF Authentication
# ─────────────────────────────────────────────────────────────────────────────

def run_wif_auth(config: Config):
    """
    Show the full WIF authentication flow:
        idira client credentials → OIDC JWT → Anthropic access token
    """
    ui.section(
        "Phase 0 — Workload Identity Federation",
        "The workload authenticates to Anthropic via idira. No static API key involved.",
        color="cyan",
    )

    auth = WIFAuthenticator(config)

    # ── Step 1: idira client credentials → JWT ──────────────────────────
    ui.show_wif_step(1, "Workload → Idira (client credentials grant)")
    ui.show_idira_request(
        config.idira_tenant_url,
        config.idira_app_id,
        config.idira_client_id,
        config.idira_scope,
    )

    ui.console.print("\n  [dim]Requesting JWT from idira...[/dim]", end="")
    try:
        idira_token = auth.get_idira_jwt()
    except RuntimeError as e:
        ui.console.print(f"\n\n[bold red]❌ idira authentication failed:[/bold red]\n{e}")
        raise SystemExit(1)

    ui.show_idira_token(idira_token)

    # ── Step 2: JWT → Anthropic WIF token ─────────────────────────────────
    ui.show_wif_step(
        2,
        "idira JWT → Anthropic (RFC 7523 jwt-bearer grant)",
        "Anthropic validates the JWT signature via idira's JWKS, then mints a short-lived access token.",
    )
    ui.show_anthropic_exchange_request(config)

    ui.console.print("\n  [dim]Exchanging JWT for Anthropic access token...[/dim]", end="")
    try:
        anthropic_token = auth.exchange_for_anthropic_token(idira_token.raw)
    except RuntimeError as e:
        ui.console.print(f"\n\n[bold red]❌ Anthropic WIF exchange failed:[/bold red]\n{e}")
        raise SystemExit(1)

    ui.show_anthropic_token(anthropic_token)
    ui.show_wif_summary(idira_token, anthropic_token)

    return idira_token, anthropic_token


# ─────────────────────────────────────────────────────────────────────────────
#  Phase 1 — Agent Demo (RFC 8693 + WIF)
# ─────────────────────────────────────────────────────────────────────────────

def run_agent_demo(alert: str, user_sub: str, access_token: str, workload_identity: str):
    """
    Housing benefit claim processed by three AI agents (fictitious Gov sector).
      - All Claude calls use the WIF-derived access token (no API key)
      - The audit trail shows the idira workload identity + RFC 8693 actor chain
      - No Operator intervenes — the accountability trail is the only safety net
    """
    ui.section(
        "Phase 1 — Benefit Claim Processing (RFC 8693 Token Exchange)",
        "Each agent-to-agent hop goes through the STS. The full delegation chain is preserved in the JWT.",
        color="green",
    )

    from rich.panel import Panel
    ui.console.print(Panel(
        "[yellow]⚠  Demo simplification — STS agent authentication[/yellow]\n\n"
        "In this demo, the [bold]orchestrator[/bold] calls sts.exchange() on behalf of each agent,\n"
        "passing the agent name as a plain string (requesting_agent=\"Orchestration-Agent\").\n\n"
        "In a real deployment, each agent would run as an [bold]independent workload[/bold]\n"
        "with its own cryptographic identity (SPIFFE JWT-SVID, Kubernetes service account\n"
        "token, or mTLS certificate). The agent would call the STS [bold]itself[/bold], and the\n"
        "STS would verify that credential before processing the exchange — so no agent\n"
        "could impersonate another.\n\n"
        "[dim]What IS real here: token audience-locking, act chain nesting, registry\n"
        "policy enforcement, and short TTLs — the structural RFC 8693 story is correct.[/dim]",
        border_style="yellow",
        title="[bold yellow]ℹ  Simplification Note[/bold yellow]",
    ))
    ui.console.print()

    # Create shared Anthropic client (WIF token — no API key)
    client = make_client(access_token)
    sts    = SecurityTokenService()
    audit: list[dict] = []

    oncall       = OrchestrationAgent(client)
    investigation = VerificationAgent(client)
    monitoring   = ApprovalAgent(client)

    # ── Step 0: Citizen submits claim ─────────────────────────────────────
    ui.console.print("[green]● Step 0[/green]  Citizen submits claim → STS mints root token\n")
    session = sts.mint_session_token(user_sub, first_agent="Orchestration-Agent")
    ui.console.print(f"  [green]👤 Citizen:[/green]  [white]{user_sub}[/white]")
    ui.console.print(
        f"  [green]→ Workload identity (idira):[/green] [cyan]{workload_identity}[/cyan]\n"
        f"  [green]→ Root token minted for:[/green] [yellow]Orchestration Agent[/yellow]  "
        f"[dim](TTL 5 min, audience-locked)[/dim]\n"
    )
    root_display = {k: v for k, v in session["payload"].items() if k not in ("iat", "exp")}
    from rich.syntax import Syntax
    ui.console.print(Syntax(json.dumps(root_display, indent=2), "json", theme="monokai"))

    # ── Step 1: Orchestration Agent ───────────────────────────────────────
    ui.console.print("\n[green]● Step 1[/green]  Orchestration Agent — receives claim, delegates verification\n")
    assessment = oncall.analyze(alert)
    ui.agent_box(
        "Orchestration Agent",
        f"Auth: idira WIF  |  Token sub: {user_sub}  |  No act chain yet (first agent)",
        assessment, "green",
    )
    audit.append({
        "caller":  "Orchestration-Agent",
        "action":  "Claim received / verification delegated",
        "subject": user_sub,
        "chain":   "Orchestration-Agent",
        "auth":    "✅",
    })

    t1 = sts.exchange(session["token"], requesting_agent="Orchestration-Agent", target="Verification-Agent")
    ui.show_sts_exchange("Orchestration-Agent", "Verification-Agent", t1["payload"])

    # ── Step 2: Verification Agent ────────────────────────────────────────
    ui.console.print("\n[green]● Step 2[/green]  Verification Agent — cross-checks national ID, income records, residency\n")
    findings = investigation.investigate(alert, assessment)
    act2 = t1["payload"].get("act", {})
    ui.agent_box(
        "Verification Agent",
        f"Auth: idira WIF  |  Token sub: {user_sub}  |  Delegated by: Orchestration Agent",
        findings, "cyan",
    )
    chain2 = flatten_act(act2) + " → Verification-Agent"
    audit.append({
        "caller":  "Verification-Agent",
        "action":  "Cross-checked registries / eligibility verdict returned",
        "subject": user_sub,
        "chain":   chain2,
        "auth":    "✅",
    })

    t2 = sts.exchange(t1["token"], requesting_agent="Verification-Agent", target="Approval-Agent")
    ui.show_sts_exchange("Verification-Agent", "Approval-Agent", t2["payload"])

    # ── Step 3: Approval Agent ────────────────────────────────────────────
    ui.console.print("\n[green]● Step 3[/green]  Approval Agent — reviews verdict, approves claim, triggers payment\n")
    action = monitoring.act(alert, findings)
    act3 = t2["payload"].get("act", {})
    ui.agent_box(
        "Approval Agent",
        f"Auth: idira WIF  |  Token sub: {user_sub}  |  Chain: orchestration → verification → approval",
        action, "magenta",
    )
    chain3 = flatten_act(act3) + " → Approval-Agent"
    audit.append({
        "caller":  "Approval-Agent",
        "action":  f"Decision: {action[:42]}…",
        "subject": user_sub,
        "chain":   chain3,
        "auth":    "✅",
    })

    # ── Audit Trail ────────────────────────────────────────────────────────
    ui.console.print()
    ui.audit_table(audit, "✅  Audit Trail — Full Provenance (WIF + RFC 8693) — No Operator involved")

    # ── Final JWT ──────────────────────────────────────────────────────────
    ui.console.print()
    ui.console.print("[bold]Final JWT payload — what the payment API receives at the last hop:[/bold]")
    final_display = {k: v for k, v in t2["payload"].items() if k not in ("iat", "exp")}
    from rich.syntax import Syntax
    ui.console.print(Syntax(json.dumps(final_display, indent=2), "json", theme="monokai"))

    sid = t2["payload"].get("session_id", "?")
    ui.console.print()
    from rich.panel import Panel
    ui.console.print(Panel(
        f"[green]Audit Board: \"Who approved this housing benefit payment?\"\nAnswer:\n"
        f"  🏢 [bold]IdP:[/bold]        Idira ({workload_identity})\n"
        f"  👤 [bold]Citizen:[/bold]    {user_sub}\n"
        f"  🔵 [bold]Chain:[/bold]      Orchestration Agent → Verification Agent → Approval Agent\n"
        f"  🔑 [bold]Session:[/bold]    {sid}\n"
        f"  🚫 [bold]API Key:[/bold]    None — WIF token only (sk-ant-oat01-...)\n"
        f"  ⏱  [bold]Tokens:[/bold]    Short-lived (WIF: 1h · STS: 5 min), cryptographically signed\n"
        f"  📋 [bold]Policy:[/bold]     idira controls workload auth · STS controls agent delegation\n"
        f"  ⚖️  [bold]Compliance:[/bold] Every automated decision is traceable — no anonymous agent action\n\n"
        f"[bold]→ No Operator reviewed this. Full accountability. No ambiguity.[/bold][/green]",
        border_style="green",
        title="[bold green]Accountability (v1)[/bold green]",
    ))


# ─────────────────────────────────────────────────────────────────────────────
#  Key Takeaways
# ─────────────────────────────────────────────────────────────────────────────

def show_takeaways():
    ui.section("Key Takeaways", color="white")

    from rich.table import Table
    rows = [
        ("⚖️ ", "Automated decisions demand stronger accountability, not less",
         "No Operator = the audit trail is the only safety net"),
        ("🚫", "No static API key stored anywhere",
         "WIF tokens are minted on demand, expire in minutes"),
        ("🏢", "idira is the source of truth for workload identity",
         "Centralized IdP — consistent policy across all Gov workloads"),
        ("🔄", "RFC 7523 jwt-bearer exchange at workload startup",
         "Benefit-processing service → idira JWT → Anthropic WIF token"),
        ("⛓ ", "RFC 8693 actor chain at every agent boundary",
         "Orchestration → Verification → Approval: each hop cryptographically linked"),
        ("📋", "Full chain: IdP → Workload → Citizen → Agent → Agent",
         "Every actor and every decision is verifiable and attributable"),
        ("🛡 ", "Compromise of any token is blast-radius-limited",
         "Short TTL + audience-locking + registry policy enforcement"),
    ]

    t = Table(show_header=False, box=None, padding=(0, 2))
    t.add_column("icon", width=3)
    t.add_column("point",  style="bold white",  min_width=42)
    t.add_column("detail", style="dim",         min_width=44)
    for icon, point, detail in rows:
        t.add_row(icon, point, detail)
    ui.console.print(t)

    from rich.panel import Panel
    ui.console.print()
    ui.console.print(Panel(
        "[dim]Further reading:[/dim]\n"
        "  • Anthropic WIF:     https://platform.claude.com/docs/en/manage-claude/workload-identity-federation\n"
        "  • RFC 7523 (WIF):   https://www.rfc-editor.org/rfc/rfc7523\n"
        "  • RFC 8693 (STS):   https://datatracker.ietf.org/doc/html/rfc8693\n"
        "  • Idira: https://docs.cyberark.com",
        border_style="bright_black",
    ))
    ui.console.print()


# ─────────────────────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    ui.banner()

    # Safety guard: WIF tokens shadow API keys per Anthropic credential precedence.
    # If ANTHROPIC_API_KEY is set, WIF will still be used (we bypass the SDK env resolution
    # by calling the WIF endpoint directly), but warn the user anyway.
    if os.environ.get("ANTHROPIC_API_KEY"):
        from rich.panel import Panel
        ui.console.print(Panel(
            "[yellow]⚠  ANTHROPIC_API_KEY is set in your environment.\n"
            "   This demo uses WIF (not the API key) — the key is ignored.\n"
            "   For a clean WIF setup, unset ANTHROPIC_API_KEY.[/yellow]",
            border_style="yellow",
        ))
        ui.console.print()

    # Load and validate config
    try:
        config = Config.from_env()
    except EnvironmentError as e:
        from rich.panel import Panel
        ui.console.print(Panel(
            f"[red]{e}[/red]",
            border_style="red",
            title="[bold red]Configuration Error[/bold red]",
        ))
        raise SystemExit(1)

    # ── Scenario ────────────────────────────────────────────────────────────
    alert    = (
        "CLAIM #2024-HB-004821: Housing benefit application submitted by citizen "
        "adam (National ID: FR-847291-2024). Declared annual income: €10,000. "
        "Claimed residency: 14 avenue des Gobelins, 75013 Paris. "
        "Awaiting automated eligibility determination — no Operator assigned."
    )
    user_sub = "adam@sme-access.com"

    from rich.panel import Panel
    ui.console.print(Panel(
        f"[bold yellow]🏛️  Housing Benefit Claim — Government Portal[/bold yellow]\n\n"
        f"[white]{alert}[/white]\n\n"
        f"[dim]Submitted by:[/dim] [cyan]{user_sub}[/cyan]\n"
        f"[dim]Three AI agents will process this claim: "
        f"Orchestration → Verification → Approval[/dim]\n\n"
        f"[bold red]No Operator will review this decision.[/bold red] "
        f"[dim]Full accountability is non-negotiable.[/dim]\n\n"
        f"[dim]This demo has two phases:[/dim]\n"
        f"  [cyan]Phase 0[/cyan] — WIF authentication (idira → Anthropic, no API key)\n"
        f"  [green]Phase 1[/green] — Claim processing (RFC 8693 actor chain with WIF token)",
        border_style="yellow",
    ))

    # ── Phase 0: WIF Auth ────────────────────────────────────────────────────
    ui.console.print("\n  Press [bold]Enter[/bold] to run WIF authentication…", end="")
    input()

    idira_token, anthropic_token = run_wif_auth(config)

    # ── Phase 1: Agent Demo ──────────────────────────────────────────────────
    ui.console.print("\n\n  Press [bold]Enter[/bold] to run the agent demo…", end="")
    input()

    run_agent_demo(
        alert=alert,
        user_sub=user_sub,
        access_token=anthropic_token.access_token,
        workload_identity=idira_token.subject,
    )

    show_takeaways()


if __name__ == "__main__":
    main()
