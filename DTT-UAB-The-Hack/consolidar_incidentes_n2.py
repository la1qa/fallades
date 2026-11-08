#!/usr/bin/env python3
"""Crea UN ticket por cadena confirmada; no confirma hipótesis ni llama a IA.

Requisitos: ticket individual de cada alerta y confirmación humana vigente.
    python consolidar_incidentes_n2.py --group INC-XXXXXXXXXXXX
    python consolidar_incidentes_n2.py --all
"""
from __future__ import annotations
import argparse
import json
from datetime import datetime,timezone
from pathlib import Path
from correlacion_n2_v3 import (indice_grupos, leer_json, guardar_json,
                              revision_vigente, ticket_ubicacion, firma_tickets, NIVELES)

ROOT = Path(__file__).resolve().parent
DESTINO = ROOT / 'resultados/v3/incidentes'


def unicos(items):
    vistos=set(); salida=[]
    for item in items:
        key=json.dumps(item,sort_keys=True,ensure_ascii=False)
        if key not in vistos:
            salida.append(item);vistos.add(key)
    return salida


def consolidar(root:Path, grupo:dict):
    """Solo agrupa un grupo de eventos ya revisado y con firmas todavía vigentes."""
    if not revision_vigente(root,grupo):
        raise ValueError('Grupo pendiente de confirmación humana o revisión caducada')
    alert_ids=sorted(set(grupo['alert_ids']))
    if len(alert_ids)<2:
        raise ValueError('Se necesitan dos alertas o más')
    tickets=[]
    for aid in alert_ids:
        path=ticket_ubicacion(root,aid)
        if path is None:
            raise ValueError('No existe ticket para '+aid)
        t=leer_json(path)
        if aid not in t.get('alert_ids',[]):
            raise ValueError('Referencia a ticket inconsistente '+aid)
        if t.get('severity') not in NIVELES:
            raise ValueError('Severidad inválida en '+aid)
        tickets.append(t)
    nivel=max((t['severity'] for t in tickets),key=NIVELES.index)
    veredictos={t.get('verdict') for t in tickets}
    if 'true_positive' in veredictos:
        veredicto='true_positive'
    elif veredictos <= {'benign_true_positive','false_positive'}:
        # Confirmación causal no demuestra por sí sola intención maliciosa.
        veredicto='needs_more_info'
    else:
        veredicto='needs_more_info'
    afectados={k:unicos([elem for t in tickets
                         for elem in (t.get('affected') or {}).get(k,[])])
               for k in ('users','hosts','business_services','customers')}
    evidencias=unicos([e for t in tickets for e in t.get('evidence',[]) if isinstance(e,dict)])
    enriquecimiento=unicos([e for t in tickets for e in t.get('enrichment',[]) if isinstance(e,dict)])
    acciones=unicos([a for t in tickets for a in t.get('recommended_actions',[]) if isinstance(a,dict)])
    preguntas=unicos([q for t in tickets for q in t.get('open_questions',[])])
    mitre=unicos([m for t in tickets for m in t.get('mitre',[])])
    gid=grupo['id']
    ticket={
        'ticket_id':'SOC-'+gid, 'alert_ids':alert_ids,
        'title':'Cadena correlacionada y confirmada: '+str(grupo.get('criterio','correlación')),
        'verdict':veredicto,'confidence':min(float(t.get('confidence',0.5)) for t in tickets),
        'severity':nivel,
        'severity_rationale':('Severidad oficial del incidente: máximo de los tickets N1 '
                              f'calculados con matriz SOC ({nivel}). Sin ajustes extra por correlación.'),
        'affected':afectados,
        'summary':('Agrupación validada por analista: '+gid+'. Evidencias de '+str(len(alert_ids))+
                   ' alertas conservadas abajo. Causalidad según registro de revisión humana.'),
        'evidence':evidencias, 'enrichment':enriquecimiento, 'mitre':mitre,
        'recommended_actions':acciones or [{'action':'Revisar cadena','target':gid,
                                            'requires_approval':False,
                                            'justification':'Validar alcance y decisiones de contención.'}],
        'executed_actions':[],
        'escalation':{'escalate':True,'to':'N2','reason':'Cadena de eventos confirmada por analista.'},
        'open_questions':preguntas,'triage_seconds':sum(float(t.get('triage_seconds',0)) for t in tickets),
        'origen':'consolidacion_determinista_n2','group_id':gid,
        'confirmacion_manual':str((root/'resultados/v3/revisiones'/f'{gid}.json').relative_to(root)),
        'firmas_tickets':firma_tickets(root,alert_ids),
        'generado_utc':datetime.now(timezone.utc).isoformat(),
        'advertencia':('Solo combina tickets existentes; no sustituye revisar la causalidad, '
                       'el alcance completo ni incidentes que quedan fuera de la correlación.'),
    }
    salida=root/'resultados/v3/incidentes'/f'{gid}.json'
    guardar_json(salida,ticket)
    return salida


def main():
    p=argparse.ArgumentParser(description=__doc__)
    group=p.add_mutually_exclusive_group(required=True)
    group.add_argument('--group',help='INC-ID confirmado')
    group.add_argument('--all',action='store_true',help='Todos los confirmados vigentes')
    args=p.parse_args()
    _,grupos=indice_grupos(ROOT)
    destinos=[grupos[args.group]] if args.group in grupos else []
    if args.all:
        destinos=[g for g in grupos.values() if revision_vigente(ROOT,g)]
    elif not destinos:
        p.error('No se encuentra el grupo')
    for g in destinos:
        try:print('Consolidado:',consolidar(ROOT,g))
        except (OSError,ValueError,KeyError) as exc:print('No consolidado:',g['id'],exc)
    print('Grupos procesados:',len(destinos))


if __name__=='__main__':
    main()
