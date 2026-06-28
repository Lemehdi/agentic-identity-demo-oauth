"""
Terminal UI helpers — Rich-based display for the WIF demo.
"""

import json
from datetime import datetime, timezone
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.rule import Rule
from rich.text import Text

console = Console()


# ─────────────────────────────────────────────────────────────────────────────
#  Layout
# ─────────────────────────────────────────────────────────────────────────────

def banner():
    console.print()
    console.print(Panel.fit(
        "[bold white]Agentic AI Identity Security — v1[/bold white]\n"
        "[dim]Workload Identity Federation  ·  Idira  ·  No Static Secrets[/dim]\n"
        "[dim]RFC 8693 Token Exchange  ·  JWT Actor Chains  ·  Zero Trust for AI Agents[/dim]\n\n"
        "[dim italic]by Elmehdi Aabad — Identity Security[/dim italic]",
        border_style="cyan", padding=(1, 6),
    ))
    console.print()


def section(title: str, subtitle: str = "", color: str = "cyan"):
    console.print()
    console.rule(f"[bold {color}]{title}[/bold {color}]", style=color)
    if subtitle:
        console.print(f"  [dim]{subtitle}[/dim]")
    console.print()


def agent_box(name: str, context_line: str, output: str, color: str):
    console.print(Panel(
        f"[dim]{context_line}[/dim]\n\n[white]{output}[/white]",
        title=f"[bold {color}]🤖  {name}[/bold {color}]",
        border_style=color, padding=(0, 2),
    ))


# ─────────────────────────────────────────────────────────────────────────────
#  WIF Authentication display
# ─────────────────────────────────────────────────────────────────────────────

def show_wif_step(step: int, title: str, subtitle: str = ""):
    console.print(f"\n[bold cyan]● WIF Step {step}[/bold cyan]  [white]{title}[/white]")
    if subtitle:
        console.print(f"  [dim]{subtitle}[/dim]")


def show_idira_request(tenant_url: str, app_id: str, client_id: str, scope: str):
    """Show the client credentials request (masked secret)."""
    req = {
        "endpoint":      f"{tenant_url}/oauth2/token/{app_id}",
        "grant_type":    "client_credentials",
        "client_id":     client_id,
        "client_secret": "***** (HTTP Basic auth)",
        "scope":         scope,
    }
    console.print()
    console.print("  [dim]→ idira client credentials request:[/dim]")
    console.print(Syntax(json.dumps(req, indent=2), "json", theme="monokai"))


def show_idira_token(token):
    """Display the decoded idira JWT claims."""
    from wif_auth import idiraToken
    console.print()
    console.print(
        f"  [green]✓[/green] idira JWT received  "
        f"[dim]sub:[/dim] [yellow]{token.subject}[/yellow]  "
        f"[dim]iss:[/dim] [yellow]{token.issuer}[/yellow]"
    )
    exp = token.claims.get("exp")
    if exp:
        exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc).strftime("%H:%M:%S UTC")
        console.print(f"  [dim]Expires at:[/dim] [white]{exp_dt}[/white]")
    console.print()
    console.print("  [dim]→ Decoded JWT payload (Anthropic will verify signature via JWKS):[/dim]")
    console.print(Syntax(json.dumps(token.display_claims(), indent=2), "json", theme="monokai"))


def show_anthropic_exchange_request(config):
    """Show the WIF token exchange request to Anthropic."""
    req = {
        "grant_type":         "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion":          "<idira-jwt> (see above)",
        "federation_rule_id": config.federation_rule_id,
        "organization_id":    config.organization_id,
        "service_account_id": config.service_account_id,
        "workspace_id":       config.workspace_id,
    }
    console.print()
    console.print("  [dim]→ Anthropic WIF token exchange (RFC 7523 jwt-bearer grant):[/dim]")
    console.print(Syntax(json.dumps(req, indent=2), "json", theme="monokai"))


def show_anthropic_token(token):
    """Display the resulting Anthropic WIF access token (masked)."""
    console.print()
    console.print(
        f"  [green]✓[/green] Anthropic access token minted  "
        f"[dim]type:[/dim] [yellow]{token.token_type}[/yellow]  "
        f"[dim]expires_in:[/dim] [yellow]{token.expires_in}s[/yellow]"
    )
    console.print(f"  [dim]Token (masked):[/dim] [bold green]{token.masked}[/bold green]")
    if token.scope:
        console.print(f"  [dim]Scope:[/dim] [white]{token.scope}[/white]")


def show_wif_summary(idira_token, anthropic_token):
    """Full WIF authentication summary panel."""
    console.print()
    console.print(Panel(
        f"[cyan]Workload authentication complete — no static API key used.[/cyan]\n\n"
        f"  [dim]IdP:[/dim]              Idira\n"
        f"  [dim]Workload identity:[/dim] [yellow]{idira_token.subject}[/yellow]\n"
        f"  [dim]Issuer:[/dim]           [white]{idira_token.issuer}[/white]\n"
        f"  [dim]Anthropic token:[/dim]  [bold green]{anthropic_token.masked}[/bold green]\n"
        f"  [dim]Token lifetime:[/dim]   {anthropic_token.expires_in}s "
        f"(short-lived, auto-refreshed)\n"
        f"  [dim]Scope:[/dim]            {anthropic_token.scope or 'workspace:developer'}\n\n"
        f"[bold]→ All Claude API calls below use this federated token.[/bold]",
        border_style="cyan",
        title="[bold cyan]WIF Authentication[/bold cyan]",
    ))


# ─────────────────────────────────────────────────────────────────────────────
#  RFC 8693 STS display
# ─────────────────────────────────────────────────────────────────────────────

def show_sts_exchange(from_agent: str, to_agent: str, payload: dict):
    """Display an RFC 8693 STS token exchange event."""
    console.print(
        f"\n  [dim]🔐 STS Exchange:[/dim]  "
        f"[yellow]{from_agent}[/yellow]  [dim]→[/dim]  [bold white]{to_agent}[/bold white]"
        f"  [dim](new JWT — audience-locked, TTL 5 min)[/dim]"
    )
    display = {k: v for k, v in payload.items() if k not in ("iat", "exp")}
    console.print(Syntax(json.dumps(display, indent=2), "json", theme="monokai"))


# ─────────────────────────────────────────────────────────────────────────────
#  Audit trail
# ─────────────────────────────────────────────────────────────────────────────

def audit_table(rows: list[dict], title: str):
    t = Table(title=title, border_style="bright_black", show_lines=True)
    t.add_column("Caller",           style="yellow",  min_width=22)
    t.add_column("Action",           style="white",   min_width=30)
    t.add_column("JWT Subject",      style="green",   min_width=24)
    t.add_column("Full Actor Chain", style="cyan",    min_width=36)
    t.add_column("Auth",             justify="center", min_width=5)
    for r in rows:
        t.add_row(r["caller"], r["action"], r["subject"], r["chain"], r["auth"])
    console.print(t)
