"""Tarvia SOC AI Copilot — demo N1 para UAB THE HACK / Deloitte.

Ejecutar desde DTT-UAB-The-Hack:
    python -m pip install streamlit requests jsonschema
    python -m streamlit run dashboard.py --server.address 0.0.0.0 --server.port 8501

Requisitos: API SOC en localhost:8000, DCC_API_KEY disponible en el entorno,
y agente_soc_dcc.py en esta misma carpeta.

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
from nivel2_soc import MotorNivel2

ROOT = Path(__file__).resolve().parent
ALERTS_PATH = ROOT / "03_alertas" / "alertas_muestra_desarrollo.jsonl"
ALL_ALERTS_PATH = ROOT / "03_alertas" / "alertas.jsonl"
SCHEMA_PATH = ROOT / "01_contexto" / "ticket_salida.schema.json"
LATEST_TICKET = ROOT / "ticket_generado.json"
AGENT_PATH = ROOT / "agente_soc_dcc.py"
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
        st.error("Falta agente_soc_dcc.py junto a dashboard.py")
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
    if soc_ok:
        st.success("SOC API · conectada")
    else:
        st.error("SOC API · desconectada")
    key_ok = bool(os.environ.get("DCC_API_KEY"))
    if key_ok:
        st.success("Clave DCC · configurada")
    else:
        st.warning("Falta DCC_API_KEY")
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

tab_queue, tab_ticket, tab_review, tab_nivel2 = st.tabs(["📥 Cola e investigación", "🔎 Ticket y evidencias", "👤 Revisión humana", "🧩 Nivel 2 · Correlación"])

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



# ===== NIVEL 2: CORRELACION Y CRITERIO =====
@st.cache_resource(show_spinner=False)
def cargar_motor_nivel2() -> MotorNivel2:
    return MotorNivel2(ROOT)


with tab_nivel2:
    st.header("Nivel 2 · Correlación y criterio")
    st.caption("Cálculo local y reproducible sobre las 11.061 alertas. No requiere llamadas al LLM y no modifica el ticket N1.")
    id_n2 = st.session_state.get("selected_alert_id", "ALR-20261005-000172")
    ticket_n2 = find_ticket(id_n2)
    if not ticket_n2:
        candidate = st.session_state.get("current_ticket")
        if candidate and id_n2 in candidate.get("alert_ids", []):
            ticket_n2 = candidate

    if not id_n2 or id_n2 not in by_id:
        st.info("Selecciona una alerta válida en «Cola e investigación» para aplicar el nivel 2.")
    else:
        motor = cargar_motor_nivel2()
        informe = motor.analizar(id_n2, ticket=ticket_n2)
        corr = informe["correlacion"]
        sev = informe["severidad_politica"]
        aut = informe["autorizacion"]
        crit = informe["contexto_activo"]

        st.markdown(f"**Alerta:** `{id_n2}` — {by_id[id_n2].get('rule_name', '')}")
        a,b,c,d = st.columns(4)
        a.metric("Candidatos mismo incidente", corr["mismo_incidente_candidato"]["total"] + corr["duplicado_evento"]["total"])
        b.metric("Campaña similar", corr["campana_similar"]["total"])
        c.metric("Relaciones por investigar", corr["relacion_investigar"]["total"])
        d.metric("Severidad base", sev.get("base") or "No determinada")

        st.subheader("1. Correlación de alertas (±24 h)")
        st.info("Coincidir en una ruta, IP o regla no demuestra una intrusión común. Las fusiones requieren evidencia adicional y revisión humana.")
        descriptions = [
            ("duplicado_evento", "Eventos duplicados"),
            ("mismo_incidente_candidato", "Posibles alertas del mismo incidente"),
            ("relacion_investigar", "Relación que requiere investigación"),
            ("campana_similar", "Campaña o patrón similar (no fusionar automáticamente)"),
        ]
        for category, titulo in descriptions:
            g = corr[category]
            with st.expander(f"{titulo} · {g['total']} alertas", expanded=g['total'] > 0):
                if g['alertas']:
                    st.dataframe([{
                        "Alerta": row["alert_id"], "Producto": row["producto"],
                        "Regla": row["regla"], "Diferencia (min)": row["minutos_diferencia"],
                        "Señales comunes": ", ".join(f"{k}={','.join(v[:2])}" for k,v in row["coincidencias"].items())
                    } for row in g["alertas"]], use_container_width=True, hide_index=True)
                else:
                    st.write("No se han detectado coincidencias en esta categoría.")
                if g["truncado"]:
                    st.warning("La tabla se ha limitado para facilitar la visualización; el total incluye más alertas.")

        st.subheader("2. Actividad autorizada")
        if aut["candidatos"]:
            for c in aut["candidatos"]:
                st.warning(f"Posible autorización {c['id']}: {c['titulo']}. Confirmar alcance y efectos.")
                st.write(" · ".join(c["justificaciones"]))
        else:
            st.info("Sin coincidencia estricta con los cambios reconocidos. Esto no prueba que no exista autorización.")
        st.caption(aut["zona_horaria_asumida"])

        st.subheader("3. Matriz de severidad")
        m1,m2,m3 = st.columns(3)
        m1.metric("Regla SIEM", by_id[id_n2].get("severity", "—"))
        m2.metric("Criticidad mayor", crit.get("criticidad_maxima") or "Desconocida")
        m3.metric("Resultado base", sev.get("base") or "Sin determinar")
        if ticket_n2:
            st.write(f"**Severidad propuesta por la IA:** `{ticket_n2.get('severity', '—')}`")
        for nota in sev.get("notas", []):
            st.caption(nota)
        for aviso in sev.get("avisos", []):
            st.warning(aviso)
        if crit.get("advertencia"):
            st.caption(crit["advertencia"])
        if crit.get("vip_o_privilegiados"):
            st.warning("Hay identidades VIP o privilegiadas: confirmar el ajuste de severidad correspondiente.")

        with st.expander("Detalle del informe de nivel 2 (JSON)"):
            st.json(informe)
        st.download_button("⬇️ Descargar análisis de nivel 2", data=json.dumps(informe, ensure_ascii=False, indent=2),
                           file_name=f"N2-{id_n2}.json", mime="application/json")

        st.subheader("4. Evaluación humana de agrupaciones")
        st.caption("Solo se permite registrar una agrupación confirmada entre alertas con coincidencias más fuertes. Las campañas similares se mantienen separadas.")
        cands = corr["duplicado_evento"]["alertas"] + corr["mismo_incidente_candidato"]["alertas"]
        possible = [r["alert_id"] for r in cands]
        if not possible:
            st.info("No hay candidatos suficientemente relacionados para proponer un ticket conjunto en esta alerta. Sí puedes documentar una campaña sin fusionarla.")
        with st.form(f"review_n2_{id_n2}"):
            selected = st.multiselect("Alertas a agrupar tras revisión", options=possible, disabled=not possible)
            analyst_n2 = st.text_input("Identificador del analista", key=f"analyst_n2_{id_n2}")
            argument = st.text_area("Evidencia independiente que confirma la misma intrusión", key=f"reason_n2_{id_n2}",
                                    placeholder="Explica cadena causal, origen, cronología y evidencias verificadas")
            approved = st.checkbox("He comprobado las evidencias y autorizo registrar la agrupación propuesta")
            saved = st.form_submit_button("Guardar evaluación humana de nivel 2")
        if saved:
            if not (analyst_n2.strip() and argument.strip()):
                st.error("Introduce un analista y una justificación verificable.")
            elif selected and not approved:
                st.error("Confirma la agrupación antes de guardarla.")
            else:
                dirname = ROOT / "revisiones_nivel2"
                dirname.mkdir(exist_ok=True)
                record = {
                    "alert_id": id_n2,
                    "candidatos_aprobados": selected if approved else [],
                    "evaluacion_de_campana": corr["campana_similar"]["total"],
                    "analista": analyst_n2.strip(),
                    "evidencia_independiente": argument.strip(),
                    "fecha_utc": datetime.now(timezone.utc).isoformat(),
                    "ticket_modificado": False,
                    "contencion_ejecutada": False,
                }
                (dirname / f"{id_n2}.json").write_text(json.dumps(record, ensure_ascii=False, indent=2),encoding="utf-8")
                st.success("Evaluación de nivel 2 guardada localmente. El ticket N1 no ha sido modificado.")

st.divider()
st.caption("Prototipo de hackathon: el modelo propone; el humano decide. Verificad las evidencias, la política y la severidad antes de actuar.")
