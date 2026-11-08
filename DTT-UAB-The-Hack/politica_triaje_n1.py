"""Controles deterministas N1: evidencias verificables, matriz oficial y escalado.

El LLM investiga e INTERPRETA; el código aplica la matriz SOC. No se modifica
la severidad por correlación en N1. Una evidencia existente puede seguir sin
probar su interpretación: el humano debe revisar los hallazgos.
"""
from __future__ import annotations

from urllib.parse import quote
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import re

from severidad import aplicar_a_ticket

ALIAS_FUENTE = {
    'edr': 'edr_events', 'email_gw': 'email', 'ngfw': 'firewall',
    'idp': 'idp_signins', 'ad': 'ad_events', 'cloud': 'cloudtrail',
    'ecom': 'ecom_auth', 'email': 'email',
}
FUENTES_LOG = {
    'waf', 'proxy', 'dns', 'edr_events', 'idp_signins', 'email',
    'email_clicks', 'firewall', 'vpn', 'ecom_auth', 'ecom_account',
    'cloudtrail', 'sql_audit', 'dlp', 'idp_audit', 'cicd_builds',
    'ai_gateway', 'ad_events',
}
FACTORES_PRUEBA = (
    'confirmed_execution_or_access',
    'personal_or_payment_data',
    'blocked_without_effect',
)


def verificar_evidencias(ticket: dict, alerta: dict, get, max_consultas: int = 15) -> dict:
    """Confirma que existen los IDs citados. No confunde su existencia con causalidad."""
    confirmados, no_verificados, errores = set(), [], []
    cache = {}
    consultas = 0
    for e in ticket.get('evidence', []):
        if not isinstance(e, dict):
            continue
        eid = str(e.get('event_id', '')).strip()
        source = str(e.get('source', '')).strip().lower()
        source = ALIAS_FUENTE.get(source, source)
        if source in ('alert', 'alerta', 'siem') and eid == alerta.get('alert_id'):
            continue  # Referencia válida a la alerta; NO es corroboración de log.
        if not eid or source not in FUENTES_LOG:
            no_verificados.append({'source': source, 'event_id': eid, 'motivo': 'fuente no comprobable'})
            continue
        clave = (source, eid)
        if clave not in cache:
            if consultas >= max_consultas:
                no_verificados.append({'source': source, 'event_id': eid, 'motivo': 'límite de verificaciones'})
                continue
            consultas += 1
            try:
                res = get(f'/logs/{quote(source, safe="")}', q=eid, limit=30)
                cache[clave] = any(str(item.get('event_id', '')) == eid
                                   for item in res.get('items', []) if isinstance(item, dict))
            except Exception as exc:
                errores.append(f'{source}/{eid}: {type(exc).__name__}')
                cache[clave] = False
        if cache[clave]:
            confirmados.add(eid)
        else:
            no_verificados.append({'source': source, 'event_id': eid,
                                   'motivo': 'sin coincidencia exacta en logs'})
    return {'event_ids_confirmados': sorted(confirmados),
            'citas_sin_confirmar': no_verificados, 'errores_api': errores,
            'consultas_realizadas': consultas,
            'nota': 'Se ha comprobado la existencia del evento, NO la interpretación del modelo.'}


def aplicar_controles_n1(ticket: dict, alerta: dict, get, verificacion: dict) -> dict:
    """Aplica severidad desde regla + activo y solo factores con IDs verificados."""
    previos = dict(ticket.get('factores') or {})
    pruebas = ticket.get('pruebas_factores') or {}
    ids_reales = set(verificacion.get('event_ids_confirmados', []))
    factores = {}
    descartados = []
    for key in FACTORES_PRUEBA:
        evidencias = pruebas.get(key, []) if isinstance(pruebas, dict) else []
        if not isinstance(evidencias, list):
            evidencias = []
        aceptado = bool(previos.get(key)) and bool(ids_reales.intersection(evidencias))
        factores[key] = aceptado
        if previos.get(key) and not aceptado:
            descartados.append(key)
    # N1 no recibe incrementos adicionales por coincidencias de grupos.
    if factores['confirmed_execution_or_access'] or factores['personal_or_payment_data']:
        factores['blocked_without_effect'] = False
    factores['correlation'] = 'none'
    ticket['factores_propuestos_modelo'] = previos
    ticket['factores'] = factores
    ticket['verificacion_evidencias'] = verificacion
    ticket['factores_descartados_sin_prueba'] = descartados

    aplicar_a_ticket(ticket, [alerta], get)
    ticket['severity_rationale'] += (
        ' Ajustes de ejecución, datos y bloqueo solo con referencias a eventos'
        ' contrastados. Correlación N2 excluida de la severidad N1.'
    )
    # Una cita de evento inventada/errónea no puede justificar el cierre automático.
    if not ids_reales:
        ticket['verdict'] = 'needs_more_info'
        ticket['confidence'] = min(float(ticket.get('confidence', 0)), 0.25)
        ticket.setdefault('open_questions', []).append(
            'No se pudo corroborar ningún ID de evento citado en 04_logs; revisar manualmente.'
        )
        # Recalcular la severidad si el cambio de veredicto eliminó un tope de benigno.
        aplicar_a_ticket(ticket, [alerta], get)
        ticket['severity_rationale'] += ' Veredicto pendiente: sin eventos contrastados.'
    elif ticket.get('verdict') == 'benign_true_positive':
        # Comprobar existencia y franja temporal de los CHG mencionados.
        # El alcance operacional del cambio requiere además revisión humana.
        base = str(ticket.get('authorization_basis') or '').strip()
        refs = re.findall(r'CHG-\d{4}-\d+', base)
        cambio_ok = True
        razones = []
        if refs:
            cambio_ok = False
            for ref in refs:
                try:
                    cambios = get('/changes', q=ref)
                    event = datetime.fromisoformat(alerta['created_at'].replace('Z', '+00:00'))
                    local = event.astimezone(ZoneInfo('Europe/Madrid')).replace(tzinfo=None)
                    for cambio in cambios:
                        if cambio.get('id') != ref:
                            continue
                        inicio = datetime.strptime(cambio['inicio'], '%Y-%m-%d %H:%M')
                        fin = datetime.strptime(cambio['fin'], '%Y-%m-%d %H:%M')
                        if inicio <= local <= fin:
                            cambio_ok = True
                            razones.append(f'{ref} existe y coincide en fecha (alcance por revisar)')
                        else:
                            razones.append(f'{ref} fuera de su ventana aprobada')
                except (TypeError, ValueError, KeyError, OSError) as exc:
                    razones.append(f'{ref} no verificado: {type(exc).__name__}')
        else:
            razones.append('Flujo sin identificador CHG: verificar política interna, actor y alcance manualmente')
        ticket['auditoria_autorizacion'] = {'referencias': refs, 'cambio_en_fecha': cambio_ok,
                                           'observaciones': razones,
                                           'nota': 'Fechas de cambios interpretadas en Europe/Madrid; comprobar alcance.'}
        if len(base) < 25 or not cambio_ok:
            ticket['verdict'] = 'needs_more_info'
            ticket['confidence'] = min(float(ticket.get('confidence', 0)), 0.4)
            ticket.setdefault('open_questions', []).append(
                'Falta demostrar autorización por actor, origen, destino, horario y política/cambio.'
            )
            aplicar_a_ticket(ticket, [alerta], get)
            ticket['severity_rationale'] += ' Actividad benigna aún no acreditada.'

    nivel = ticket['severity']
    veredicto = ticket['verdict']
    debe_escalar = (veredicto == 'true_positive' and nivel in ('high','critical')) or (
        veredicto == 'needs_more_info' and nivel in ('high','critical'))
    if debe_escalar:
        ticket['escalation'] = {
            'escalate': True,
            'to': 'N2 de guardia' if nivel == 'critical' else 'N2',
            'reason': ('Política SOC: severidad ' + nivel +
                       ' con veredicto ' + veredicto + '; revisión humana prioritaria.'),
        }
    if ticket.get('escalation', {}).get('escalate'):
        ticket['decision_n1'] = 'escalar_a_N2'
    elif ticket['verdict'] in ('benign_true_positive', 'false_positive'):
        ticket['decision_n1'] = 'proponer_cierre_tras_revision'
    else:
        ticket['decision_n1'] = 'investigar_mas_y_revision_humana'
    # Evitar contradicciones: un caso pendiente o escalable no se puede presentar
    # con una recomendación de cierre como única acción.
    acciones = ticket.get('recommended_actions') or []
    if ticket['decision_n1'] != 'proponer_cierre_tras_revision':
        acciones = [a for a in acciones if not (
            isinstance(a, dict) and re.search(r'\b(cerrar|cierre|descartar|close|dismiss)\b',
                                              str(a.get('action', '')).lower())
        )]
    if ticket['decision_n1'] == 'escalar_a_N2' and not any(
        isinstance(a, dict) and re.search(r'escalar|escalat', str(a.get('action','')), re.I)
        for a in acciones
    ):
        acciones.append({'action':'Escalar ticket a N2', 'target':alerta['alert_id'],
                         'requires_approval':False,
                         'justification':'Escalado obligatorio o revisión N2 prioritaria por política SOC.'})
    ticket['recommended_actions'] = acciones
    if not ticket.get('recommended_actions'):
        ticket['recommended_actions'] = [{
            'action': 'Revisar evidencias y decidir cierre o escalado',
            'target': alerta['alert_id'], 'requires_approval': False,
            'justification': 'El sistema no ha podido justificar otra actuación.',
        }]
    # Se registra DESPUÉS de cualquier recálculo: aplicar_a_ticket reemplaza severity_calc.
    ticket['severity_calc']['factor_checks'] = {
        'event_ids_confirmados': verificacion.get('event_ids_confirmados', []),
        'factores_descartados': descartados,
        'nota': 'Un ID existente no demuestra por sí mismo éxito, autorización o causalidad.',
    }
    return ticket
