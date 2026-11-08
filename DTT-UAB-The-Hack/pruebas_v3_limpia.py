#!/usr/bin/env python3
"""Pruebas V3 offline (sin Deloitte y sin gastar llamadas a ornith)."""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import correlacion_n2_v3 as corr
import agente_soc_dcc_v3 as v3

FIXTURE_DIR = Path(__file__).resolve().parent
SCHEMA_ORIG = FIXTURE_DIR / '01_contexto' / 'ticket_salida.schema.json'


def ticket(aid, event_id, source='vpn', severity='medium', verdict='true_positive'):
    return {'ticket_id':f'SOC-{aid}','alert_ids':[aid],'title':'Prueba de incidente',
            'verdict':verdict,'severity':severity,'confidence':0.9,
            'evidence':[{'source':source,'event_id':event_id,'finding':'Evento observado'}]}


class V3Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=Path(self.tmp.name)
        self.grupo={'id':'INC-TEST01','alert_ids':['ALR-1','ALR-2'],
                    'criterio':'user_host','puntuacion_regla':85,
                    'inicio':'2026-10-10T01:00:00Z','fin':'2026-10-10T02:00:00Z'}
        corr.guardar_json(self.root / corr.GRUPOS,[self.grupo])
        corr.guardar_json(self.root/corr.TICKETS_V2/'ALR-1.json', ticket('ALR-1','VPN-01'))
        corr.guardar_json(self.root/corr.TICKETS_V2/'ALR-2.json', ticket('ALR-2','EDR-02','edr_events'))
        (self.root/'04_logs').mkdir()
        (self.root/'04_logs/vpn.jsonl').write_text('{"event_id":"VPN-01"}\n')
        (self.root/'04_logs/edr_events.jsonl').write_text('{"event_id":"EDR-02"}\n')

    def tearDown(self):
        self.tmp.cleanup()

    def test_contexto_corto_y_preliminar(self):
        c=corr.contexto_alerta(self.root,'ALR-1')
        self.assertEqual(c['grupos_candidatos'][0]['relacionadas'],['ALR-2'])
        self.assertEqual(c['grupos_candidatos'][0]['estado'],'hipotesis_no_confirmada')
        self.assertLess(len(json.dumps(c)),850)

    def test_una_ip_no_confirma(self):
        r=corr.evaluar_riesgo_n2(self.root,ticket('ALR-1','VPN-01'),'ALR-1')
        self.assertEqual((r['delta_correlacion_n2'],r['severity_n2_contextual']),(0,'medium'))

    def test_veredicto_desconocido_se_marca_sin_inventar(self):
        t=corr.normalizar_veredicto({'verdict':'investigando','severity':'critical',
                                    'confidence':0.98,'open_questions':[]},'ALR-1')
        self.assertEqual(t['verdict'],'needs_more_info')
        self.assertEqual(t['severity'],'critical')
        self.assertEqual(t['confidence'],0.25)
        self.assertIn('investigando',t['open_questions'][0])

    def test_veredicto_valido_se_preserva(self):
        t=corr.normalizar_veredicto({'verdict':'true_positive','confidence':0.9,
                                     'open_questions':[]}, 'ALR-1')
        self.assertEqual(t['verdict'],'true_positive')
        self.assertEqual(t['confidence'],0.9)

    def test_no_es_cadena_sin_dos_eventos_validos(self):
        with self.assertRaises(ValueError):
            corr.confirmar_grupo(self.root,'INC-TEST01','Analista', 'c'*60,
                                ['ALR-1=VPN-01','ALR-2=NO_EXISTE'])
        self.assertFalse((self.root/corr.REVISIONES/'INC-TEST01.json').exists())

    def _confirmar(self):
        corr.confirmar_grupo(self.root,'INC-TEST01','Analista N2',
                            'Los eventos describen acceso inicial y ejecución relacionada, '
                            'según revisión de origen, usuario, tiempo y actividad posterior.',
                            ['ALR-1=VPN-01','ALR-2=EDR-02'])

    def test_confirmacion_humana_permite_plus_solo_en_auditoria(self):
        self._confirmar()
        t=corr.leer_json(self.root/corr.TICKETS_V2/'ALR-1.json')
        r=corr.evaluar_riesgo_n2(self.root,t,'ALR-1')
        self.assertEqual(r['delta_correlacion_n2'],1)
        self.assertEqual(r['severity_n1_oficial'],'medium')
        self.assertEqual(r['severity_n2_contextual'],'high')
        self.assertEqual(corr.leer_json(self.root/corr.TICKETS_V2/'ALR-1.json')['severity'],'medium')
        self.assertEqual(corr.evaluar_riesgo_n2(self.root,t,'ALR-1')['severity_n2_contextual'],'high')

    def test_benigno_no_aumenta_ni_disminuye(self):
        self._confirmar()
        t=ticket('ALR-1','VPN-01',verdict='benign_true_positive')
        r=corr.evaluar_riesgo_n2(self.root,t,'ALR-1')
        self.assertEqual(r['delta_correlacion_n2'],0)
        self.assertEqual(r['severity_n2_contextual'],'medium')

    def test_aprobacion_caduca_al_modificar_ticket(self):
        self._confirmar()
        ruta=self.root/corr.TICKETS_V2/'ALR-2.json'
        t=corr.leer_json(ruta)
        t['summary']='Evidencia corregida después de aprobación'
        corr.guardar_json(ruta,t)
        r=corr.evaluar_riesgo_n2(self.root, ticket('ALR-1','VPN-01'),'ALR-1')
        self.assertEqual(r['delta_correlacion_n2'],0)

    def test_grupo_modificado_invalida_confirmacion(self):
        self._confirmar()
        nuevo=dict(self.grupo,alert_ids=['ALR-1','ALR-3'])
        corr.guardar_json(self.root/corr.GRUPOS,[nuevo])
        r=corr.evaluar_riesgo_n2(self.root, ticket('ALR-1','VPN-01'),'ALR-1')
        self.assertEqual(r['delta_correlacion_n2'],0)

    def test_integracion_agente_con_modelo_simulado(self):
        """Ejecuta agente_main con el SDK simulado y el schema REAL; sin red."""
        from jsonschema import validate
        fuente = Path(__file__).resolve().parent
        # Si hay dataset local en directorio repo: tomar el schema de allí.
        esquema=SCHEMA_ORIG if SCHEMA_ORIG.exists() else fuente/'test_schema.json'
        if not esquema.is_file():
            self.skipTest('No se adjuntó el esquema del reto; las pruebas de lógica sí se ejecutan')
        (self.root/'01_contexto/runbooks').mkdir(parents=True)
        shutil.copy2(esquema,self.root/'01_contexto/ticket_salida.schema.json')
        (self.root/'01_contexto/politica_soc.md').write_text('Politica N1; no ajustar por correlacion')
        (self.root/'01_contexto/runbooks/RB-02.md').write_text('Investigar EDR')
        # Ticket de ejemplo realista conforme a JSON schema oficial.
        ejemplo={
          'ticket_id':'SOC-TEST','alert_ids':['ALR-1'],'title':'Acceso sospechoso',
          'verdict':'investigando','confidence':0.95,'severity':'critical',
          'severity_rationale':'Regla critical; recurso relevante, sin cambio por correlacion.',
          'affected':{'users':[],'hosts':[],'business_services':[],'customers':[]},
          'summary':'Se requieren más registros para identificar la actividad y verificar el incidente.',
          'evidence':[{'source':'edr_events','event_id':'EDR-02','finding':'Detección EDR observada'}],
          'enrichment':[],'mitre':[],
          'recommended_actions':[{'action':'Revisar actividad','target':'analista N2',
                                  'requires_approval':False,'justification':'Falta verificación'}],
          'escalation':{'escalate':True,'to':'N2','reason':'Severidad crítica; revisión obligatoria'},
          'open_questions':[]
        }
        fake=types.ModuleType('agents')
        fake.Agent=lambda **kwargs: types.SimpleNamespace(**kwargs)
        fake.function_tool=lambda f:f
        fake.AsyncOpenAI=lambda **kwargs:object()
        fake.OpenAIChatCompletionsModel=lambda **kwargs:object()
        fake.set_tracing_disabled=lambda **kwargs:None
        class FakeRunner:
            @staticmethod
            def run_sync(agent,prompt,max_turns):
                data=json.loads(prompt)
                assert data['contexto_correlacion_preliminar']['grupos_candidatos']
                assert data['alerta']['alert_id']=='ALR-1'
                return types.SimpleNamespace(final_output=types.SimpleNamespace(model_dump=lambda:dict(ejemplo)))
        fake.Runner=FakeRunner
        alerta={'alert_id':'ALR-1','runbook':'RB-02','created_at':'2026-10-10T00:00:00Z'}
        with patch.dict(sys.modules,{'agents':fake}), patch.object(v3,'ROOT',self.root),\
             patch.dict(os.environ,{'LLM_PROVIDER':'dcc','DCC_API_KEY':'test_only_not_real'}),\
             contextlib.redirect_stdout(io.StringIO()):
            v3.agente_main(alerta)
        salida=self.root/corr.TICKETS_V3/'ALR-1.json'
        self.assertTrue(salida.exists())
        t=corr.leer_json(salida)
        self.assertEqual(t['verdict'],'needs_more_info')
        self.assertEqual(t['severity'],'critical')
        self.assertEqual(t['confidence'],0.25)
        validate(instance=t,schema=corr.leer_json(esquema))
        self.assertEqual(corr.leer_json(self.root/'resultados/v3/auditorias/ALR-1.json')['delta_correlacion_n2'],0)
        self.assertTrue((self.root/corr.TICKETS_V2/'ALR-1.json').is_file())
        self.assertFalse((self.root/'ticket_generado.json').exists())


if __name__=='__main__':
    unittest.main(verbosity=2)
