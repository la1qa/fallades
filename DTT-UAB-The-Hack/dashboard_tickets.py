"""Cola local de tickets SOC.

Ejecutar desde DTT-UAB-The-Hack:
    python -m streamlit run dashboard_tickets.py

Lee únicamente JSON locales de tickets/ y no ejecuta acciones de contención.

py -3.10 -m pip install streamlit
py -3.10 -m streamlit run .\dashboard_tickets.pyclear
"""

from __future__ import annotations

import json
import html
import re
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parent
TICKETS_DIR = ROOT / "resultados" / "tickets"
STATUS_DIR = ROOT / "resultados" / "ticket_status"
ACTIONS_DIR = ROOT / "resultados" / "ticket_actions"
FALLBACK_TICKET = ROOT / "ticket_generado.json"

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
}
SEVERITY_COLOR = {
    "critical": "#620d74",
    "high": "#e60c0c",
    "medium": "#eea21f",
    "low": "#e0e323",
    "informational": "#45e37c",
}
SEVERITY_TINT = {
    "critical": "rgba(98, 13, 116, 0.18)",
    "high": "rgba(230, 12, 12, 0.18)",
    "medium": "rgba(238, 162, 31, 0.18)",
    "low": "rgba(224, 227, 35, 0.18)",
    "informational": "rgba(69, 227, 124, 0.18)",
}
SEVERITY_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
}

st.set_page_config(
    page_title="Tarvia SOC | Ticket queue",
    page_icon=":)",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .block-container {
        max-width: 1500px;
        padding-top: 3rem;
        padding-left: 2rem;
        padding-right: 2rem;
    }
    .queue-card {
        border: 1px solid #263648; border-radius: 4px; padding: 3px 6px;
        margin: 0; background: #111d2a;
    }
    .severity-dot {
        display: inline-block; width: 10px; height: 10px; border-radius: 50%;
        margin-right: 7px;
    }
    .muted { color: #94a3b8; font-size: 0.88rem; }
    [data-testid="stTable"] {
        width: 100% !important;
    }
    [data-testid="stTable"] table {
        width: 100% !important;
        table-layout: fixed !important;
    }
    [data-testid="stTable"] th,
    [data-testid="stTable"] td {
        white-space: normal !important;
        overflow-wrap: anywhere !important;
        word-break: break-word !important;
        vertical-align: top !important;
    }
    .evidence-table {
        width: 100%;
        table-layout: fixed;
        border-collapse: collapse;
        font-size: 14px;
    }
    .evidence-table .evidence-source { width: 15%; }
    .evidence-table .evidence-event { width: 25%; }
    .evidence-table .evidence-finding { width: 60%; }
    .evidence-table th, .evidence-table td {
        padding: 8px 10px;
        text-align: left;
        vertical-align: top;
        white-space: normal;
        overflow-wrap: anywhere;
        word-break: break-word;
        border-bottom: 1px solid rgba(148, 163, 184, 0.2);
    }
    /* Reduce vertical spacing between Streamlit elements */
    div[data-testid="stVerticalBlock"] {
        gap: 0.25rem;
    }

    div[data-testid="stElementContainer"] {
        margin-bottom: 0 !important;
    }

    /* Compact ticket buttons */
    div[data-testid="stButton"] {
        margin: 0 !important;
        padding: 0 !important;
    }

    div[data-testid="stButton"] button {
        min-height: 34px;
        padding: 3px 7px;
        margin: 0 !important;
        line-height: 1.1;
        border-radius: 4px;
    }
    /* Queue: no vertical spacing */
    .st-key-queue-list [data-testid="stVerticalBlock"] {
        gap: 0 !important;
    }

    .st-key-queue-list [data-testid="stElementContainer"] {
        margin: 0 !important;
        padding: 0 !important;
    }

    /* Ticket cards */
    .st-key-queue-list div[data-testid="stButton"] {
        margin: 0 !important;
    }

    .st-key-queue-list div[data-testid="stButton"] button {
        width: calc(100% - 4px);
        box-sizing: border-box;
        min-height: 42px;
        height: auto;
        border-radius: 0 !important;
        padding: 8px 10px;
        text-align: left;
        white-space: normal !important;
        line-height: 1.3;
        transition: background 0.15s ease;
    }

    .st-key-queue-list div[data-testid="stButton"] button p {
        white-space: normal !important;
    }
    .st-key-queue-list div[data-testid="stButton"] button::before {
        content: "";
        display: inline-block;
        width: 9px;
        height: 9px;
        min-width: 9px;
        border-radius: 50%;
        margin-right: 10px;
        vertical-align: middle;
    }
    /* Severity filter pills follow the same palette as queue cards. */
    .st-key-severity-filter div[data-baseweb="tag"]:nth-of-type(1),
    .st-key-severity-filter div[data-baseweb="tag"]:nth-of-type(1) > div {
        background: rgba(98, 13, 116, 0.22) !important;
        border-color: #620d74 !important;
    }
    .st-key-severity-filter div[data-baseweb="tag"]:nth-of-type(2),
    .st-key-severity-filter div[data-baseweb="tag"]:nth-of-type(2) > div {
        background: rgba(230, 12, 12, 0.22) !important;
        border-color: #e60c0c !important;
    }
    .st-key-severity-filter div[data-baseweb="tag"]:nth-of-type(3),
    .st-key-severity-filter div[data-baseweb="tag"]:nth-of-type(3) > div {
        background: rgba(238, 162, 31, 0.22) !important;
        border-color: #eea21f !important;
    }
    .st-key-severity-filter div[data-baseweb="tag"]:nth-of-type(4),
    .st-key-severity-filter div[data-baseweb="tag"]:nth-of-type(4) > div {
        background: rgba(224, 227, 35, 0.28) !important;
        border-color: #e0e323 !important;
    }
    .st-key-severity-filter div[data-baseweb="tag"]:nth-of-type(5),
    .st-key-severity-filter div[data-baseweb="tag"]:nth-of-type(5) > div {
        background: rgba(69, 227, 124, 0.22) !important;
        border-color: #45e37c !important;
    }
    .st-key-status-filter div[data-baseweb="tag"]:nth-of-type(1),
    .st-key-status-filter div[data-baseweb="tag"]:nth-of-type(1) > div {
        background: rgba(245, 158, 11, 0.18) !important;
        border-color: #d97706 !important;
    }
    .st-key-status-filter div[data-baseweb="tag"]:nth-of-type(2),
    .st-key-status-filter div[data-baseweb="tag"]:nth-of-type(2) > div {
        background: rgba(107, 114, 128, 0.18) !important;
        border-color: #6b7280 !important;
    }
    .st-key-severity-critical,
    .st-key-severity-high,
    .st-key-severity-medium,
    .st-key-severity-low,
    .st-key-severity-informational,
    .st-key-status-open,
    .st-key-status-fixed {
        border: 1px solid transparent;
        border-radius: 6px;
        padding: 2px 8px;
        margin: 2px 0;
    }
    .st-key-severity-critical {
        background: rgba(98, 13, 116, 0.18);
        border-color: #620d74;
    }
    .st-key-severity-high {
        background: rgba(230, 12, 12, 0.18);
        border-color: #e60c0c;
    }
    .st-key-severity-medium {
        background: rgba(238, 162, 31, 0.18);
        border-color: #eea21f;
    }
    .st-key-severity-low {
        background: rgba(224, 227, 35, 0.22);
        border-color: #e0e323;
    }
    .st-key-severity-informational {
        background: rgba(69, 227, 124, 0.18);
        border-color: #45e37c;
    }
    .st-key-status-open {
        background: rgba(245, 158, 11, 0.16);
        border-color: #d97706;
    }
    .st-key-status-fixed {
        background: rgba(107, 114, 128, 0.16);
        border-color: #6b7280;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def load_tickets() -> list[dict]:
    tickets: list[dict] = []
    if TICKETS_DIR.is_dir():
        paths = sorted(TICKETS_DIR.glob("*.json"))
    else:
        paths = []
    if not paths and FALLBACK_TICKET.is_file():
        paths = [FALLBACK_TICKET]

    for path in paths:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict) or not data.get("ticket_id"):
            continue
        data["_file"] = path.name
        status_path = STATUS_DIR / f"{data['ticket_id']}.json"
        try:
            saved_status = json.loads(status_path.read_text(encoding="utf-8")).get("status")
        except (FileNotFoundError, OSError, ValueError, AttributeError):
            saved_status = None
        data["_status"] = str(saved_status or data.get("status", "open")).lower()
        tickets.append(data)
    return tickets


def severity(ticket: dict) -> str:
    value = str(ticket.get("severity", "informational")).lower()
    return value if value in SEVERITY_ORDER else "informational"


def status(ticket: dict) -> str:
    value = str(ticket.get("_status", "open")).lower()
    return "fixed" if value in {"fixed", "closed", "resolved"} else "open"


def load_action_state(ticket_id: str, action_count: int) -> list[bool]:
    path = ACTIONS_DIR / f"{ticket_id}.json"
    try:
        completed = json.loads(path.read_text(encoding="utf-8")).get("completed", [])
    except (FileNotFoundError, OSError, ValueError, AttributeError):
        completed = []
    return [
        bool(completed[index]) if index < len(completed) else False
        for index in range(action_count)
    ]


def save_action_state(ticket_id: str, completed: list[bool]) -> None:
    ACTIONS_DIR.mkdir(parents=True, exist_ok=True)
    path = ACTIONS_DIR / f"{ticket_id}.json"
    payload = {
        "ticket_id": ticket_id,
        "completed": completed,
        "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def save_ticket_status(ticket_id: str, fixed: bool) -> None:
    STATUS_DIR.mkdir(parents=True, exist_ok=True)
    path = STATUS_DIR / f"{ticket_id}.json"
    payload = {
        "ticket_id": ticket_id,
        "status": "fixed" if fixed else "open",
        "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def save_fixed_from_title(ticket_id: str) -> None:
    try:
        save_ticket_status(ticket_id, bool(st.session_state[f"fixed-{ticket_id}"]))
    except OSError as exc:
        st.error(f"No se pudo guardar el estado: {exc}")


def alert_datetime(ticket: dict) -> datetime | None:
    alert_ids = ticket.get("alert_ids") or [ticket.get("alert_id")]
    for alert_id in alert_ids:
        match = re.search(r"(?<!\d)(\d{8})(?:-\d{6})?(?!\d)", str(alert_id))
        if match:
            raw_date = match.group(1)
            try:
                return datetime.strptime(raw_date, "%Y%m%d")
            except ValueError:
                continue
    return None


def format_time(ticket: dict) -> str:
    alert_date = alert_datetime(ticket)
    if alert_date:
        return alert_date.strftime("%Y-%m-%d")
    value = ticket.get("created_at") or ticket.get("timestamp")
    return str(value) if value else "Sin fecha"


def sort_datetime(ticket: dict) -> datetime:
    return alert_datetime(ticket) or datetime.max


def render_badge(value: str, color: str | None = None) -> None:
    color = color or "#64748b"
    st.markdown(
        f'<span style="display:inline-block;background:{color};color:#fff;'
        f'border-radius:999px;padding:3px 9px;font-size:.78rem;font-weight:700">'
        f"{value.upper()}</span>",
        unsafe_allow_html=True,
    )


def render_json_section(title: str, value: object) -> None:
    if value not in (None, "", [], {}):
        st.html(
            f"""
            <div style="
                font-family: inherit;
                font-size: 15px;
                line-height: 12px;
                font-weight: 700;
                color: #94a3b8;
                margin: 6px 0 2px 0;
                padding: 0;
            ">{html.escape(title)}</div>
            """
        )
        if title == "Evidencias" and isinstance(value, list):
            render_evidence_table(value)
        elif isinstance(value, dict):
            st.table([
                {
                    "Campo": str(key).replace("_", " ").title(),
                    "Detalle": format_table_value(item),
                }
                for key, item in value.items()
            ])
        elif isinstance(value, list):
            if all(isinstance(item, dict) for item in value):
                keys = {key for row in value for key in row}
                st.table([
                    {
                        str(key).replace("_", " ").title(): format_table_value(item.get(key))
                        for key in keys
                    }
                    for item in value
                ])
            else:
                st.table([{"Detalle": format_table_value(item)} for item in value])
        else:
            st.table([{"Detalle": str(value)}])


def render_evidence_table(evidence: list[object]) -> None:
    rows = []
    for item in evidence:
        if not isinstance(item, dict):
            rows.append(
                f"<tr><td colspan='3'>{html.escape(format_table_value(item))}</td></tr>"
            )
            continue
        rows.append(
            "<tr>"
            f"<td>{html.escape(format_table_value(item.get('source')))}</td>"
            f"<td>{html.escape(format_table_value(item.get('event_id')))}</td>"
            f"<td>{html.escape(format_table_value(item.get('finding')))}</td>"
            "</tr>"
        )
    st.html(
        """
        <table class="evidence-table">
            <colgroup>
                <col class="evidence-source">
                <col class="evidence-event">
                <col class="evidence-finding">
            </colgroup>
            <thead>
                <tr><th>Fuente</th><th>Evento</th><th>Hallazgo</th></tr>
            </thead>
            <tbody>%s</tbody>
        </table>
        """
        % "".join(rows)
    )


def render_text_section(title: str, value: object) -> None:
    if value not in (None, "", [], {}):
        st.html(
            f"""
            <div style="
                font-family: inherit;
                font-size: 15px;
                line-height: 12px;
                font-weight: 700;
                color: #94a3b8;
                margin: 6px 0 2px 0;
                padding: 0;
            ">{html.escape(title)}</div>
            """
        )
        st.markdown(str(value))


def render_wrapped_list_section(title: str, value: object) -> None:
    if not value:
        return
    items = value if isinstance(value, list) else [value]
    rows = "".join(
        f'<li style="padding:7px 0;border-bottom:1px solid rgba(148,163,184,.2);'
        f'white-space:normal;overflow-wrap:anywhere;word-break:break-word;">'
        f'{html.escape(format_table_value(item))}</li>'
        for item in items
    )
    st.html(
        f"""
        <div style="font-size:15px;line-height:12px;font-weight:700;
                    color:#94a3b8;margin:6px 0 2px">{html.escape(title)}</div>
        <ul style="width:100%;margin:0;padding:0 0 0 18px;font-size:14px;
                   line-height:1.45">{rows}</ul>
        """
    )


def format_table_value(value: object) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value) if value not in (None, "") else "—"


def render_escalation(value: object) -> None:
    if not isinstance(value, dict):
        render_json_section("Escalado", value)
        return
    escalate = bool(value.get("escalate"))
    color = "#ef4444" if escalate else "#22c55e"
    destination = format_table_value(value.get("to", "No especificado"))
    reason = format_table_value(value.get("reason", "Sin justificación"))
    heading = "TRASLADAR A SOPORTE / N2" if escalate else "NO REQUIERE TRASLADO"
    st.markdown(
        f"""
        <div style="border:1px solid {color};border-left:7px solid {color};
                    border-radius:8px;padding:12px 16px;margin:8px 0 12px;
                    background:var(--secondary-background-color, #f8fafc);
                    color:var(--text-color, #1e293b)">
            <div style="color:{color};font-size:16px;font-weight:700">
                {heading}
            </div>
            <div style="margin-top:7px"><b>Destino:</b> {html.escape(destination)}</div>
            <div style="margin-top:5px;color:var(--text-color, #334155)">
                <b>Motivo:</b> {html.escape(reason)}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_pie_chart(
    title: str,
    tickets: list[dict],
    categories: list[tuple[str, str, str]],
    value_getter,
) -> None:
    counts = {
        key: sum(value_getter(ticket) == key for ticket in tickets)
        for key, _, _ in categories
    }
    total = sum(counts.values())
    if not total:
        st.info("No hay tickets para mostrar.")
        return

    start = 0.0
    segments = []
    for key, _, color in categories:
        if counts[key]:
            end = start + counts[key] / total * 360
            segments.append(f"{color} {start:.2f}deg {end:.2f}deg")
            start = end
    gradient = ", ".join(segments)
    legend = "".join(
        f"""
        <div style="display:flex;align-items:center;gap:8px;margin:7px 0">
            <span style="width:11px;height:11px;border-radius:50%;
                         background:{color};display:inline-block"></span>
            <span>{html.escape(label)}</span>
            <strong style="margin-left:auto">{counts[key]}</strong>
        </div>
        """
        for key, label, color in categories
        if counts[key]
    )
    st.html(
        f"""
        <div style="font-size:18px;font-weight:700;margin:22px 0 8px">
            {html.escape(title)}
        </div>
        <div style="display:flex;justify-content:center">
            <div style="width:210px;height:210px;border-radius:50%;
                        background:conic-gradient({gradient})"></div>
        </div>
        <div style="width:100%;font-size:14px;margin-top:12px">
            {legend}
        </div>
        """
    )


def render_verdict_pie(tickets: list[dict]) -> None:
    verdicts = [
        ("true_positive", "True positive", "#ef4444"),
        ("benign_true_positive", "Benign true positive", "#22c55e"),
        ("false_positive", "False positive", "#f59e0b"),
        ("needs_more_info", "Needs more info", "#3b82f6"),
    ]
    render_pie_chart(
        "Tickets por tipo de veredicto",
        tickets,
        verdicts,
        lambda ticket: str(ticket.get("verdict", "")).lower(),
    )


def render_severity_pie(tickets: list[dict]) -> None:
    severities = [
        (key, SEVERITY_LABEL[key], SEVERITY_COLOR[key])
        for key in SEVERITY_ORDER
    ]
    render_pie_chart(
        "Tickets por severidad",
        tickets,
        severities,
        lambda ticket: severity(ticket),
    )


def render_action_tasklist(ticket: dict) -> None:
    actions = ticket.get("recommended_actions") or []
    st.html(
        '<div style="font-size:15px;font-weight:700;color:#94a3b8;'
        'margin:10px 0 4px;">Plan de acciones</div>'
    )
    if not actions:
        st.info("No hay acciones recomendadas.")
        return

    ticket_id = str(ticket["ticket_id"])
    completed = load_action_state(ticket_id, len(actions))
    with st.form(f"actions-form-{ticket_id}"):
        for index, action in enumerate(actions):
            if isinstance(action, dict):
                action_text = str(action.get("action", "Acción sin descripción"))
                target = action.get("target")
                justification = action.get("justification")
                detail = " · ".join(
                    str(value) for value in (target, justification) if value
                )
                label = f"{action_text}{f' — {detail}' if detail else ''}"
            else:
                label = str(action)
            completed[index] = st.checkbox(
                label,
                value=completed[index],
                key=f"action-{ticket_id}-{index}",
            )
        submitted = st.form_submit_button(
            "Guardar progreso de acciones",
            use_container_width=True,
        )
    if submitted:
        try:
            save_action_state(ticket_id, completed)
        except OSError as exc:
            st.error(f"No se pudo guardar el progreso: {exc}")
        else:
            st.success("Progreso de acciones guardado.")
            st.rerun()


tickets = load_tickets()
tickets.sort(
    key=lambda item: (
        1 if status(item) == "fixed" else 0,
        SEVERITY_ORDER[severity(item)],
        sort_datetime(item),
    )
)

with st.sidebar:
    st.title("Tarvia SOC")
    st.caption("Plataforma web interna del SOC para consultar, analizar y gestionar las alertas de seguridad de Tarvia, facilitando su priorización y seguimiento.")
    if st.button("↻ Recargar tickets", use_container_width=True):
        st.rerun()

    st.markdown("**Filtrar por severidad**")
    selected_severities = [
        sev for sev in SEVERITY_ORDER
        if st.checkbox(
            SEVERITY_LABEL[sev],
            value=True,
            key=f"severity-{sev}",
        )
    ]
    st.markdown("**Filtrar por estado**")
    selected_status = [
        state for state, label in (("open", "Abiertos"), ("fixed", "Fixed"))
        if st.checkbox(label, value=True, key=f"status-{state}")
    ]
    query = st.text_input("Buscar", placeholder="ID, título, host, regla...")

filtered = [
    ticket
    for ticket in tickets
    if severity(ticket) in selected_severities
    and status(ticket) in selected_status
    and (
        not query
        or query.lower()
        in json.dumps(ticket, ensure_ascii=False).lower()
    )
]

if "selected_ticket" not in st.session_state:
    st.session_state.selected_ticket = None
if st.session_state.selected_ticket not in {
    ticket.get("ticket_id") for ticket in filtered
}:
    st.session_state.selected_ticket = None

left, right = st.columns([0.32, 0.67], gap="large")

with left:
    st.subheader("Cola de alertas")
    st.caption(f"{len(filtered)} visibles · {len(tickets)} tickets cargados")
    if not filtered:
        st.info("No hay tickets que coincidan con los filtros.")
    with st.container(key="queue-list", height=760, border=False):
        for ticket in filtered:
            ticket_id = str(ticket["ticket_id"])
            sev = severity(ticket)
            fixed = status(ticket) == "fixed"
            title = str(ticket.get("title", "Sin título"))
            label = f"{'✓ ' if fixed else ''}{title} · {format_time(ticket)}"
            selected = ticket_id == st.session_state.selected_ticket
            card_background = (
                "rgba(100, 116, 139, 0.22)"
                if fixed and selected
                else "rgba(100, 116, 139, 0.12)" if fixed
                else SEVERITY_TINT[sev]
            )
            card_border = "#6b7280" if fixed else (
                "#f8fafc" if selected else SEVERITY_COLOR[sev]
            )
            dot_color = SEVERITY_COLOR[sev]
            border_width = "2px" if selected else "1px"
            button_scope = f".st-key-ticket-{ticket_id}"
            st.markdown(
                f"""
                <style>
                {button_scope} button {{
                    background: {card_background} !important;
                    border: {border_width} solid {card_border} !important;
                    box-shadow: {"inset 4px 0 0 " + dot_color if selected else "none"};
                    transition: filter .15s ease, box-shadow .15s ease;
                    translate: none;
                }}
                {button_scope} button:hover {{
                    background: {card_background} !important;
                    filter: brightness(1.12);
                }}
                {button_scope} button::before {{
                    content: "";
                    display: inline-block;
                    width: 9px;
                    height: 9px;
                    min-width: 9px;
                    border-radius: 50%;
                    background: {dot_color};
                    margin-right: 10px;
                    vertical-align: middle;
                }}
                </style>
                """,
                unsafe_allow_html=True,
            )
            if st.button(
                label,
                key=f"ticket-{ticket_id}",
                use_container_width=True,
            ):
                st.session_state.selected_ticket = ticket_id
                st.rerun()

with right:
    selected = next(
        (ticket for ticket in filtered if ticket["ticket_id"] == st.session_state.selected_ticket),
        None,
    )
    detail_color = SEVERITY_COLOR[severity(selected)] if selected else "#64748b"
    st.markdown(
        f"""
        <style>
        .stHorizontalBlock:has(.detail-accent) > div:nth-child(2) {{
            border-left: 10px solid {detail_color};
            padding-left: 22px;
            min-height: 760px;
        }}
        </style>
        <div class="detail-accent"></div>
        """,
        unsafe_allow_html=True,
    )
    if selected is None:
        st.title("Resumen de la cola")
        total_tickets = len(filtered)
        fixed_tickets = sum(status(ticket) == "fixed" for ticket in filtered)
        open_tickets = total_tickets - fixed_tickets
        st.html(
            f"""
            <div style="display:flex;gap:12px;width:100%;margin:12px 0 8px">
                <div style="flex:1;padding:16px 18px;border-radius:10px;
                            border:1px solid rgba(59,130,246,.45);
                            background:rgba(59,130,246,.12)">
                    <div style="font-size:13px;color:#64748b">TOTAL DE TICKETS</div>
                    <div style="font-size:30px;font-weight:800">{total_tickets}</div>
                </div>
                <div style="flex:1;padding:16px 18px;border-radius:10px;
                            border:1px solid rgba(34,197,94,.55);
                            background:rgba(34,197,94,.12)">
                    <div style="font-size:13px;color:#64748b">SOLUCIONADOS</div>
                    <div style="font-size:30px;font-weight:800;color:#16a34a">
                        {fixed_tickets}
                    </div>
                </div>
                <div style="flex:1;padding:16px 18px;border-radius:10px;
                            border:1px solid rgba(245,158,11,.55);
                            background:rgba(245,158,11,.12)">
                    <div style="font-size:13px;color:#64748b">PENDIENTES</div>
                    <div style="font-size:30px;font-weight:800;color:#d97706">
                        {open_tickets}
                    </div>
                </div>
            </div>
            """
        )
        chart_left, chart_right = st.columns(2, gap="large")
        with chart_left:
            render_verdict_pie(filtered)
        with chart_right:
            render_severity_pie(filtered)
    else:
        if st.button("← Volver al dashboard", key="back-to-dashboard"):
            st.session_state.selected_ticket = None
            st.rerun()

        sev = severity(selected)
        st.html(
            f"""
            <div style="font-family:inherit;font-size:24px;line-height:1.5;
                        font-weight:700;margin:0 0 10px;color:inherit">
                {html.escape(str(selected.get("title", selected["ticket_id"])))}
            </div>
            """
        )
        render_badge(SEVERITY_LABEL[sev], SEVERITY_COLOR[sev])

        st.markdown(
            f"**Veredicto:** `{selected.get('verdict', 'unknown')}`  ·  "
            f"**Confianza:** `{selected.get('confidence', '—')}`"
        )
        format_time_str = format_time(selected)
        st.markdown(f"{format_time_str}")
        render_escalation(selected.get("escalation"))
        render_text_section("Resumen", selected.get("summary"))

        render_action_tasklist(selected)

        render_text_section("Por qué esta severidad", selected.get("severity_rationale"))
        render_json_section("Activos y entidades afectadas", selected.get("affected"))
        render_json_section("Evidencias", selected.get("evidence"))
        render_json_section("Enriquecimiento", selected.get("enrichment"))
        render_wrapped_list_section("MITRE", selected.get("mitre"))
        render_wrapped_list_section("Preguntas abiertas", selected.get("open_questions"))

        st.divider()
        current_fixed = status(selected) == "fixed"
        with st.form(f"status-form-{selected['ticket_id']}"):
            fixed = st.checkbox("Marcar como solucionado", value=current_fixed)
            save_fixed = st.form_submit_button(
                "Guardar estado del ticket",
                use_container_width=True,
            )
        if save_fixed:
            try:
                save_ticket_status(selected["ticket_id"], fixed)
            except OSError as exc:
                st.error(f"No se pudo guardar el estado: {exc}")
            else:
                st.success("Estado del ticket guardado.")
                st.rerun()

        st.markdown(f"**Ticket:** `{selected['ticket_id']}`")
        st.markdown(f"**Archivo:** `{selected.get('_file', '—')}`")

        with st.expander("JSON completo"):
            st.json({key: value for key, value in selected.items() if not key.startswith("_")})
