"""
Dashboard Live para visualizacion en tiempo real de atacante + observador.

Usa Rich Layout + Live para split-screen:
  +---------------------------------------------------+
  | HEADER: scenario, target, models, elapsed         |
  +-------------------------+-------------------------+
  | ATACANTE                | OBSERVADOR              |
  | tactic, last action,    | window, last classify,  |
  | progress, replans       | triage signals          |
  +-------------------------+-------------------------+
  | TIMELINE (last 12 events, mixed)                  |
  +---------------------------------------------------+

Diseño minimalista. Activable via --dashboard flag en main.py para no romper
los logs estandar de Rich que ya existen.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from datetime import datetime
from typing import TYPE_CHECKING

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from src.ui.session import SessionEvent


def _short(s, n: int) -> str:
    s = str(s)
    return s[:n] + "..." if len(s) > n else s


class LiveDashboard:
    """Dashboard que se actualiza en background mientras corre el ataque."""

    def __init__(self, scenario: str = "", target: str = "",
                 attacker_model: str = "", observer_model: str = ""):
        self.scenario = scenario
        self.target = target
        self.attacker_model = attacker_model
        self.observer_model = observer_model
        self._start_time = time.monotonic()

        # Estado en vivo
        self.attacker_tactic = "—"
        self.attacker_last_action = "—"
        self.attacker_replans = 0
        self.attacker_actions = 0
        self.attacker_tactics_done = 0
        self.attacker_total_tactics = 0

        self.observer_window = "—"
        self.observer_last_classify = "—"
        self.observer_confidence = 0.0
        self.observer_signals = 0
        self.observer_classifications = 0

        self.recent_events: deque = deque(maxlen=12)
        self._lock = threading.Lock()
        self._live: Live | None = None
        self._stopped = False

    def start(self) -> None:
        if self._live is not None:
            return
        layout = self._build_layout()
        # Usamos un Console nuevo (no el global) para que Live tenga su propio
        # output. Los console.print del resto del codigo siguen funcionando.
        console = Console()
        self._live = Live(layout, console=console, refresh_per_second=4,
                          screen=False, transient=False)
        self._live.start()

    def stop(self) -> None:
        self._stopped = True
        if self._live is not None:
            try:
                # Render final
                self._live.update(self._build_layout(), refresh=True)
                self._live.stop()
            except Exception:
                pass
            self._live = None

    def push_event(self, event: "SessionEvent") -> None:
        """Recibe un evento del SessionRecorder y actualiza estado."""
        with self._lock:
            self._update_from_event(event)
            self.recent_events.append(event)
            if self._live is not None and not self._stopped:
                try:
                    self._live.update(self._build_layout())
                except Exception:
                    pass

    def _update_from_event(self, ev: "SessionEvent") -> None:
        # SessionEvent.tactic es top-level para attacker; observer usa payload.
        et = ev.event_type
        if ev.agent == "attacker":
            if et == "tactic_start":
                self.attacker_tactic = ev.tactic or ev.payload.get("tactic", "?")
            elif et == "tool_call":
                tool = ev.payload.get("tool", "?")
                self.attacker_last_action = tool
                self.attacker_actions += 1
            elif et == "replan":
                self.attacker_replans += 1
            elif et == "objective_check":
                if ev.payload.get("success"):
                    self.attacker_tactics_done += 1
        elif ev.agent == "observer":
            if et == "window_start":
                ws = ev.payload.get("window_start", "")[-8:]
                we = ev.payload.get("window_end", "")[-8:]
                self.observer_window = f"{ws} — {we}"
            elif et == "triage":
                if ev.payload.get("result") == "signal":
                    self.observer_signals = ev.payload.get("signals_count", 0)
            elif et == "classify":
                # `tactic` puede venir en ev.tactic (record() lo extrae como
                # parametro nombrado) o en el payload, segun el call site.
                tactic = ev.tactic or ev.payload.get("tactic", "?")
                self.observer_last_classify = tactic
                self.observer_confidence = ev.payload.get("confidence", 0.0)
                self.observer_classifications += 1

    def _build_layout(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(self._render_header(), size=3, name="header"),
            Layout(name="middle"),
            Layout(self._render_timeline(), size=14, name="timeline"),
        )
        layout["middle"].split_row(
            Layout(self._render_attacker_panel(), name="attacker"),
            Layout(self._render_observer_panel(), name="observer"),
        )
        return layout

    def _render_header(self) -> Panel:
        elapsed = int(time.monotonic() - self._start_time)
        h, rem = divmod(elapsed, 3600)
        m, s = divmod(rem, 60)
        elapsed_str = f"{h:d}h {m:02d}m {s:02d}s" if h else f"{m:d}m {s:02d}s"

        text = Text()
        text.append("Scenario: ", style="dim")
        text.append(f"{self.scenario}", style="bold cyan")
        text.append("  |  Target: ", style="dim")
        text.append(self.target, style="bold yellow")
        text.append("  |  Atacante: ", style="dim")
        text.append(_short(self.attacker_model, 30), style="red")
        text.append("  |  Observer: ", style="dim")
        text.append(_short(self.observer_model, 30), style="blue")
        text.append("  |  Elapsed: ", style="dim")
        text.append(elapsed_str, style="bold green")
        return Panel(text, title="[bold]Sistema Adversarial MITRE ATT&CK[/bold]",
                      border_style="white")

    def _render_attacker_panel(self) -> Panel:
        table = Table.grid(padding=(0, 1))
        table.add_column(style="bold red", width=12)
        table.add_column()
        table.add_row("Tactica:", Text(self.attacker_tactic, style="bold"))
        table.add_row("Tacticas:", f"{self.attacker_tactics_done}/{self.attacker_total_tactics or '?'}")
        table.add_row("Acciones:", str(self.attacker_actions))
        table.add_row("Replans:", str(self.attacker_replans))
        table.add_row("Last tool:", Text(_short(self.attacker_last_action, 50), style="cyan"))
        return Panel(table, title="[red]ATACANTE[/red]", border_style="red")

    def _render_observer_panel(self) -> Panel:
        table = Table.grid(padding=(0, 1))
        table.add_column(style="bold blue", width=14)
        table.add_column()
        table.add_row("Ventana:", Text(self.observer_window, style="dim"))
        table.add_row("Clasifica:", Text(self.observer_last_classify, style="bold"))
        table.add_row("Confianza:", f"{self.observer_confidence:.0%}")
        table.add_row("Señales:", str(self.observer_signals))
        table.add_row("Total class.:", str(self.observer_classifications))
        return Panel(table, title="[blue]OBSERVADOR[/blue]", border_style="blue")

    def _render_timeline(self) -> Panel:
        if not self.recent_events:
            return Panel(Text("(esperando eventos)", style="dim"),
                         title="[bold]Timeline (ultimos 12)[/bold]")
        lines = []
        for ev in self.recent_events:
            try:
                ts = datetime.fromisoformat(ev.timestamp.replace("Z", "+00:00")).strftime("%H:%M:%S")
            except Exception:
                ts = ev.timestamp[:8]
            agent_color = {"attacker": "red", "observer": "blue", "system": "white"}.get(ev.agent, "white")
            agent_label = ev.agent[:4].upper()
            desc = self._format_event_desc(ev)
            line = Text()
            line.append(f"{ts} ", style="dim")
            line.append(f"{agent_label:4} ", style=agent_color)
            line.append(desc[:120])
            lines.append(line)
        body = Text("\n").join(lines)
        return Panel(body, title="[bold]Timeline (ultimos 12 eventos)[/bold]",
                     border_style="white")

    def _format_event_desc(self, ev) -> str:
        et = ev.event_type
        p = ev.payload
        # Attacker events: tactic vive en ev.tactic (top-level del SessionEvent).
        tactic = ev.tactic or p.get("tactic", "?")
        if et == "tactic_start":
            return f"→ {tactic} iniciada"
        if et == "tool_call":
            tool = p.get("tool", "?")
            args = p.get("args", {})
            args_brief = ", ".join(f"{k}={_short(v, 30)}" for k, v in list(args.items())[:2])
            return f"{tool}({args_brief})"
        if et == "tool_result":
            return f"  result: {p.get('size', 0)} chars"
        if et == "objective_check":
            ok = "✓" if p.get("success") else "✗"
            return f"{ok} {tactic}: {_short(p.get('reason', ''), 80)}"
        if et == "replan":
            return f"replan #{p.get('attempt', 0)}: {_short(p.get('feedback', ''), 70)}"
        if et == "tactic_end":
            ok = "✓" if p.get("success") else "✗"
            return f"{ok} {tactic} cerrada"
        if et == "memory_match":
            return f"🧠 fp={_short(p.get('fingerprint', ''), 12)} ({p.get('runs_previas', 0)} runs)"
        if et == "memory_save":
            return "💾 playbook actualizado"
        if et == "triage":
            return f"triage: {p.get('result', '?')} ({p.get('signals_count', 0)} señales)"
        if et == "classify":
            return f"→ {tactic} ({p.get('confidence', 0):.0%})"
        if et == "refine":
            return f"refine #{p.get('count', 0)}"
        if et == "window_start":
            return "ventana iniciada"
        if et == "window_end":
            return "ventana cerrada"
        if et == "session_start":
            return f"sesion iniciada: {p.get('scenario', '?')}"
        if et == "error":
            return f"ERROR: {_short(p.get('message', ''), 80)}"
        return et
