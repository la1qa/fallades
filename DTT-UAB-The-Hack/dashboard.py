"""Tarvia SOC AI Copilot — demo N1 para UAB THE HACK / Deloitte.

Ejecutar desde DTT-UAB-The-Hack:
    python -m pip install streamlit requests jsonschema
    python -m streamlit run dashboard.py --server.address 0.0.0.0 --server.port 8501

Requisitos: API SOC en localhost:8000, DCC_API_KEY disponible en el entorno,
y agente_soc_dcc_v2.py en esta misma carpeta.

Seguridad: solo usa GET contra Tarvia. No ejecuta contenciones ni aprobaciones.
Las revisiones humanas se guardan en archivos locales, no en la API del SOC.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
import streamlit as st
from jsonschema import ValidationError, validate

ROOT = Path(__file__).resolve().parent
ALERTS_PATH = ROOT / "03_alertas" / "alertas_muestra_desarrollo.jsonl"
ALL_ALERTS_PATH = ROOT / "03_alertas" / "alertas.jsonl"
SCHEMA_PATH = ROOT / "01_contexto" / "ticket_salida.schema.json"
LATEST_TICKET = ROOT / "ticket_generado.json"
AGENT_PATH = ROOT / "agente_soc_dcc_v2.py"
TICKETS_DIR = ROOT / "tickets_dashboard"
REVIEWS_DIR = ROOT / "revisiones_dashboard"
LOGS_DIR = ROOT / "logs_dashboard"
LOCK_PATH = ROOT / ".dashboard_agent.lock"
BASE_URL = os.environ.get("SOC_API_URL", "http://127.0.0.1:8000").rstrip("/")
ALERT_ID_RE = re.compile(r"^ALR-\d{8}-\d{6}$")

st.set_page_config(page_title="Tarvia SOC | AI Copilot", page_icon="🛡️", layout="wide")
st.markdown(
    """<style>
    .block-container {padding-top: 1.4rem; padding-bottom: 3rem; max-width: 1480px;}
    div[data-testid="stMetric"] {background: #111d2a; border: 1px solid #263648;
      border-radius: 12px; padding: 12px 15px;}
    div[data-testid="stMetric"] label {color: #aec0ce;}
    div[data-testid="stMetric"] [data-testid="stMetricValue"] {color: #f5f8ff;}
    </style>""",
    unsafe_allow_html=True,
)


@st.cache_data(show_spinner=False)
def read_jsonl(path: str) -> list[dict]:
    result = []
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    result.append(json.loads(line))
    except FileNotFoundError:
        return []
    return result


@st.cache_data(show_spinner=False)
def read_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def api_online() -> bool:
    try:
        response = requests.get(f"{BASE_URL}/docs", timeout=2)
        return response.status_code == 200
    except requests.RequestException:
        return False


def get_alert(alert_id: str, local_by_id: dict[str, dict]) -> dict | None:
    # El fichero local permite mostrar alertas incluso si la API está apagada.
    if alert_id in local_by_id:
        return local_by_id[alert_id]
    try:
        response = requests.get(f"{BASE_URL}/alerts/{alert_id}", timeout=10)
        response.raise_for_status()
        return response.json()
    except (requests.RequestException, ValueError):
        return None


def load_ticket(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        validate(instance=data, schema=read_schema())
        return data
    except (FileNotFoundError, ValueError, OSError, ValidationError):
        return None


def find_ticket(alert_id: str) -> dict | None:
    persisted = load_ticket(TICKETS_DIR / f"{alert_id}.json")
    if persisted is not None:
        return persisted
    # Importar visualmente el ticket que ya generasteis en la terminal.
    latest = load_ticket(LATEST_TICKET)
    if latest is not None and alert_id in latest.get("alert_ids", []):
        return latest
    return None


def load_review(alert_id: str) -> dict | None:
    try:
        return json.loads((REVIEWS_DIR / f"{alert_id}.json").read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError, OSError):
        return None


def run_agent(alert_id: str, model: str, max_turns: int) -> tuple[dict | None, str]:
    """Ejecuta exactamente el CLI existente, mostrando la salida real del proceso.

    El agente original escribe un fichero global. Se utiliza un lock para impedir
    dos investigaciones simultáneas desde diferentes sesiones del dashboard.
    """
    if not AGENT_PATH.is_file():
        st.error("Falta agente_soc_dcc_v2.py junto a dashboard.py")
        return None, ""
    if not os.environ.get("DCC_API_KEY"):
        st.error("No se encuentra DCC_API_KEY en los secretos del Codespace.")
        return None, ""
    if not api_online():
        st.error("La API SOC no responde en el puerto 8000. Arranca Uvicorn primero.")
        return None, ""

    TICKETS_DIR.mkdir(exist_ok=True)
    LOGS_DIR.mkdir(exist_ok=True)
    log_path = LOGS_DIR / f"{alert_id}.log"
    view = st.empty()
    entries: list[str] = []
    output = None
    with LOCK_PATH.open("a+") as lock_file:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            st.warning("Ya hay una investigación en marcha. Espera a que termine antes de iniciar otra.")
            return None, ""

        # No confundir un ticket anterior con el de la nueva ejecución.
        old_mtime = LATEST_TICKET.stat().st_mtime_ns if LATEST_TICKET.exists() else 0
        env = os.environ.copy()
        env.update({
            "LLM_PROVIDER": "dcc",
            "DCC_MODEL": model,
            "SOC_MAX_TURNS": str(max_turns),
            "SOC_VERBOSE": "1",
            "PYTHONUNBUFFERED": "1",
        })
        command = [sys.executable, "-u", str(AGENT_PATH), alert_id]
        try:
            process = subprocess.Popen(
                command,
                cwd=ROOT,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
            with log_path.open("w", encoding="utf-8") as logfile:
                assert process.stdout is not None
                for line in process.stdout:
                    logfile.write(line)
                    logfile.flush()
                    # La salida completa del agente también incluye el JSON entero;
                    # en pantalla mostramos solo los pasos relevantes.
                    shown = line.strip()
                    if any(tag in shown for tag in (
                        "[SOC API]", "[IA]", "ALERTA:", "REGLA:",
                        "TICKET GENERADO", "Guardado en:", "Traceback",
                        "Error", "Exception", "Falta ", "No existe",
                    )):
                        entries.append(shown[:600])
                        entries = entries[-35:]
                        view.code("\n".join(entries), language="text")
                returncode = process.wait()
        except OSError as exc:
            st.error(f"No se pudo iniciar el agente: {exc}")
            return None, str(log_path)
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

        if returncode != 0:
            st.error(f"La investigación terminó con código {returncode}. Revisa el registro.")
            return None, str(log_path)
        if not LATEST_TICKET.exists() or LATEST_TICKET.stat().st_mtime_ns <= old_mtime:
            st.error("El agente terminó, pero no generó un ticket nuevo.")
            return None, str(log_path)

        output = load_ticket(LATEST_TICKET)
        if output is None or alert_id not in output.get("alert_ids", []):
            st.error("El resultado no cumple el esquema o no corresponde a esta alerta.")
            return None, str(log_path)

        (TICKETS_DIR / f"{alert_id}.json").write_text(
            json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return output, str(log_path)


def show_ticket(ticket: dict) -> None:
    st.subheader(ticket.get("title", "Ticket sin título"))
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Veredicto", ticket.get("verdict", "—"))
    col2.metric("Severidad propuesta", ticket.get("severity", "—"))
    col3.metric("Confianza declarada", f"{ticket.get('confidence', 0) * 100:.0f}%")
    col4.metric("Triaje", f"{ticket.get('triage_seconds', 0):.1f} s")
    st.caption("La confianza la estima el modelo: no es una probabilidad calibrada. Revisión humana obligatoria.")
    st.write(ticket.get("summary", "Sin resumen"))

    with st.expander("Por qué propone esta severidad", expanded=True):
        st.write(ticket.get("severity_rationale", "No proporcionado"))
        st.warning("La matriz y sus ajustes todavía requieren verificación humana; el JSON válido no prueba que el análisis sea correcto.")

    st.markdown("#### Evidencias consultadas")
    evidence = ticket.get("evidence", [])
    if evidence:
        for entry in evidence:
            st.markdown(f"**{entry.get('source', 'Fuente')} · {entry.get('event_id', '—')}**")
            st.text(entry.get("finding", ""))
    else:
        st.info("El agente no incluyó evidencias. No confirmes el resultado sin investigarlas.")

    left, right = st.columns(2)
    with left:
        st.markdown("#### Indicadores enriquecidos")
        st.dataframe(ticket.get("enrichment", []), use_container_width=True, hide_index=True)
    with right:
        st.markdown("#### Activos afectados")
        st.json(ticket.get("affected", {}), expanded=True)

    st.markdown("#### Recomendaciones")
    if ticket.get("recommended_actions"):
        st.dataframe(ticket["recommended_actions"], use_container_width=True, hide_index=True)
    else:
        st.warning("El ticket no contiene acciones recomendadas. Revisad si corresponde cerrar o escalar.")
    st.markdown("#### Escalado")
    st.json(ticket.get("escalation", {}), expanded=True)
    with st.expander("Preguntas abiertas y límites"):
        st.write(ticket.get("open_questions", []) or "Sin preguntas documentadas")
    st.download_button(
        "⬇️ Descargar ticket JSON",
        data=json.dumps(ticket, ensure_ascii=False, indent=2),
        file_name=f"{ticket.get('ticket_id', 'ticket')}.json",
        mime="application/json",
        key="download_ticket",
    )


# ===== CABECERA =====
st.title("🛡️ Tarvia SOC · AI Copilot")
st.caption("UAB THE HACK 2026 · Deloitte · Triaje N1 con modelos DCC (UAB) · Humano al mando")

all_alerts = read_jsonl(str(ALL_ALERTS_PATH))
sample = read_jsonl(str(ALERTS_PATH))
by_id = {a.get("alert_id"): a for a in all_alerts}
if not all_alerts:
    st.error("No encuentro 03_alertas/alertas.jsonl. Copia dashboard.py dentro de DTT-UAB-The-Hack.")
    st.stop()

known_ids = set()
for path in TICKETS_DIR.glob("*.json") if TICKETS_DIR.exists() else []:
    if load_ticket(path) is not None:
        known_ids.add(path.stem)
previous = load_ticket(LATEST_TICKET)
if previous:
    known_ids.update(previous.get("alert_ids", []))

with st.sidebar:
    st.header("Conexiones")
    soc_ok = api_online()
    st.success("SOC API · conectada") if soc_ok else st.error("SOC API · desconectada")
    key_ok = bool(os.environ.get("DCC_API_KEY"))
    st.success("Clave DCC · configurada") if key_ok else st.warning("Falta DCC_API_KEY")
    st.caption("La clave nunca se muestra en pantalla.")
    st.divider()
    model = st.selectbox("Modelo de la UAB", ["ornith", "nemotron"], index=0)
    max_turns = st.slider("Límite de turnos", min_value=4, max_value=18, value=12)
    st.info("Las consultas del dashboard son solo de lectura. No se ejecutará contención.")

metrics = st.columns(4)
metrics[0].metric("Alertas SIEM", f"{len(all_alerts):,}".replace(",", "."))
metrics[1].metric("Muestra de desarrollo", len(sample))
metrics[2].metric("Alertas con ticket local", len(known_ids))
metrics[3].metric("Estado", "Preparado" if soc_ok and key_ok else "Revisar conexión")

tab_queue, tab_ticket, tab_review = st.tabs(["📥 Cola e investigación", "🔎 Ticket y evidencias", "👤 Revisión humana"])

with tab_queue:
    st.subheader("Seleccionar alerta")
    selection_mode = st.radio("Origen", ["Introducir identificador", "Muestra de 150 alertas"], horizontal=True)
    if selection_mode == "Muestra de 150 alertas":
        src_filter = st.selectbox("Producto", ["Todos"] + sorted({a.get("source_product", "?") for a in sample}))
        candidates = [a for a in sample if src_filter == "Todos" or a.get("source_product") == src_filter]
        st.dataframe(
            [{"ID": a.get("alert_id"), "Fecha UTC": a.get("created_at"), "Producto": a.get("source_product"),
              "Regla": a.get("rule_name"), "Severidad inicial": a.get("severity")}
             for a in candidates],
            use_container_width=True,
            hide_index=True,
            height=240,
        )
        selected_id = st.selectbox("Alerta a investigar", [a["alert_id"] for a in candidates],
                                   format_func=lambda x: f"{x} · {by_id.get(x, {}).get('rule_name', '')}") if candidates else ""
    else:
        selected_id = st.text_input("ID de la alerta", value="ALR-20261005-000172").strip()

    if selected_id and not ALERT_ID_RE.fullmatch(selected_id):
        st.error("Introduce un identificador válido: ALR-AAAAMMDD-XXXXXX")
        selected_id = ""

    if selected_id:
        st.session_state["selected_alert_id"] = selected_id
        alert = get_alert(selected_id, by_id)
        if alert:
            a, b = st.columns([2, 1])
            with a:
                st.markdown(f"**{alert.get('rule_name', 'Alerta')}**")
                st.caption(f"{alert.get('created_at', '')} · {alert.get('source_product', '?')} · {alert.get('runbook', '')}")
                st.text(alert.get("description", ""))
            with b:
                st.metric("Severidad de la regla", alert.get("severity", "—"))
                st.caption("La severidad final debe calcularse con el contexto del activo.")
            with st.expander("Datos originales del SIEM"):
                st.json(alert)
        else:
            st.warning("No puedo recuperar esa alerta del dataset o de la API.")

        has_ticket = find_ticket(selected_id) is not None
        if has_ticket:
            st.success("Hay un ticket válido para esta alerta. Puedes revisarlo en la segunda pestaña.")
        st.divider()
        if st.button("🔍 Investigar con IA", type="primary", disabled=not (soc_ok and key_ok and alert),
                     use_container_width=True):
            st.write("**Consultas reales del agente:**")
            with st.spinner("Investigando con el modelo DCC. Las consultas aparecerán debajo…"):
                ticket, log_path = run_agent(selected_id, model, max_turns)
            if ticket:
                st.success("Ticket generado y validado con el esquema de Deloitte.")
                st.session_state["current_ticket"] = ticket
            else:
                st.error("No se generó un ticket válido. Consulta el registro de ejecución.")
            if log_path and Path(log_path).exists():
                with st.expander("Registro completo de ejecución"):
                    st.download_button(
                        "Descargar registro", Path(log_path).read_text(encoding="utf-8"),
                        file_name=Path(log_path).name, mime="text/plain",
                    )

with tab_ticket:
    current_id = st.session_state.get("selected_alert_id", "ALR-20261005-000172")
    current = st.session_state.get("current_ticket")
    if current is not None and current_id not in current.get("alert_ids", []):
        current = None
    current = current or find_ticket(current_id)
    if current:
        show_ticket(current)
    else:
        st.info("Selecciona una alerta y pulsa «Investigar con IA». También puedes ver el ticket generado previamente si eliges su ID.")

with tab_review:
    current_id = st.session_state.get("selected_alert_id", "ALR-20261005-000172")
    current = find_ticket(current_id)
    if current is None and st.session_state.get("current_ticket") and current_id in st.session_state["current_ticket"].get("alert_ids", []):
        current = st.session_state["current_ticket"]
    if not current:
        st.info("Primero necesitas un ticket válido para poder revisarlo.")
    else:
        st.write(f"**Alerta:** `{current_id}`")
        st.write(f"**Propuesta de IA:** {current.get('verdict')} · {current.get('severity')}")
        saved_review = load_review(current_id)
        if saved_review:
            st.success(f"Revisión guardada: {saved_review.get('decision', '—')} ({saved_review.get('timestamp_utc', '')})")
        with st.form("human_review"):
            decision = st.selectbox("Decisión del analista", ["Pendiente", "Confirmar cierre", "Escalar a N2", "Solicitar más información"])
            analyst = st.text_input("Analista (identificador)", placeholder="Ej.: analista-n1")
            comments = st.text_area("Motivo y observaciones", placeholder="Evidencias revisadas, discrepancias, pasos siguientes…")
            submitted = st.form_submit_button("Guardar decisión humana")
        if submitted:
            if decision == "Pendiente" or not analyst.strip() or not comments.strip():
                st.warning("Selecciona una decisión e introduce analista y una justificación.")
            else:
                REVIEWS_DIR.mkdir(exist_ok=True)
                review = {
                    "alert_id": current_id,
                    "ticket_id": current.get("ticket_id"),
                    "decision": decision,
                    "analyst": analyst.strip(),
                    "comments": comments.strip(),
                    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                    "soc_action_executed": False,
                }
                (REVIEWS_DIR / f"{current_id}.json").write_text(
                    json.dumps(review, ensure_ascii=False, indent=2), encoding="utf-8"
                )
                st.success("Revisión registrada localmente. No se ha ejecutado ninguna acción en la API SOC.")
        st.caption("Demo N1: confirmar una revisión no cierra automáticamente la alerta en el SIEM ni autoriza contención.")

st.divider()
st.caption("Prototipo de hackathon: el modelo propone; el humano decide. Verificad las evidencias, la política y la severidad antes de actuar.")
