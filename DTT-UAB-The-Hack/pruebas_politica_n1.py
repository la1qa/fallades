#!/usr/bin/env python3
"""Pruebas de integración con la API simulada y el dataset original, sin GPU."""
import copy
import sys
import unittest
from pathlib import Path
from fastapi.testclient import TestClient

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT / '06_herramientas'))
from mock_soc_api import app
from politica_triaje_n1 import aplicar_controles_n1, verificar_evidencias

API=TestClient(app)

def get(path, **params):
    r=API.get(path,params=params)
    if r.status_code==404: return {'not_found':True}
    r.raise_for_status()
    return r.json()


def ticket(verdict='true_positive', factor=False, support=True):
    return {'ticket_id':'SOC-PRUEBA','alert_ids':['ALR-20261005-000172'],
            'title':'Intento WAF','verdict':verdict,'confidence':0.9,'severity':'critical',
            'severity_rationale':'generado por IA',
            'evidence':[{'source':'waf','event_id':'WAF-0001840',
                         'finding':'Intento bloqueado según evidencia'}],
            'open_questions':[],
            'recommended_actions':[{'action':'Revisar','target':'WEB-ECOM01',
                                    'requires_approval':False,'justification':'riesgo'}],
            'escalation':{'escalate':False,'to':'','reason':'pendiente'},
            'factores':{'blocked_without_effect':factor},
            'pruebas_factores':{'blocked_without_effect':['WAF-0001840' if support else 'FAKE-999']}}


class PoliticaRealTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alerta = get('/alerts/ALR-20261005-000172')

    def evaluar(self, t, alerta=None):
        a=alerta or self.alerta
        comprobacion=verificar_evidencias(t,a,get)
        return aplicar_controles_n1(t,a,get,comprobacion)

    def test_evento_real_contrasta_en_log(self):
        verificacion=verificar_evidencias(ticket(),self.alerta,get)
        self.assertEqual(verificacion['event_ids_confirmados'],['WAF-0001840'])

    def test_waf_recurso_critico_regla_low_da_medium(self):
        t=self.evaluar(ticket())
        self.assertEqual(t['severity'],'medium')
        self.assertEqual(t['severity_calc']['criticitat']['nivel'],'Crítica')
        self.assertEqual(t['decision_n1'],'investigar_mas_y_revision_humana')

    def test_bloqueo_con_evento_aplica_un_unico_menos_uno(self):
        t=self.evaluar(ticket(factor=True))
        self.assertEqual(t['severity'],'low')

    def test_factor_sin_prueba_real_no_ajusta(self):
        t=self.evaluar(ticket(factor=True,support=False))
        self.assertEqual(t['severity'],'medium')
        self.assertIn('blocked_without_effect',t['factores_descartados_sin_prueba'])

    def test_autorizacion_ambigua_no_descarta_actividad(self):
        t=self.evaluar(ticket(verdict='benign_true_positive'))
        self.assertEqual(t['verdict'],'needs_more_info')
        self.assertEqual(t['severity'],'medium')

    def test_cambio_fuera_de_ventana_no_autoriza(self):
        t=ticket(verdict='benign_true_positive')
        t['authorization_basis']='El origen es legítimo: CHG-2026-1066 autorización de mantenimiento VPN.'
        t=self.evaluar(t)
        self.assertEqual(t['verdict'],'needs_more_info')
        self.assertFalse(t['auditoria_autorizacion']['cambio_en_fecha'])

    def test_evento_inexistente_no_se_cierra(self):
        t=ticket(verdict='false_positive')
        t['evidence'][0]['event_id']='WAF-NO-EXISTE'
        t=self.evaluar(t)
        self.assertEqual(t['verdict'],'needs_more_info')
        self.assertEqual(t['decision_n1'],'investigar_mas_y_revision_humana')

    def test_recalculo_con_evento_no_verificado_conserva_auditoria(self):
        t=ticket(verdict='false_positive',factor=True)
        t['evidence'][0]['event_id']='WAF-NO-EXISTE'
        t=self.evaluar(t)
        self.assertEqual(t['verdict'],'needs_more_info')
        self.assertIn('factor_checks',t['severity_calc'])
        self.assertEqual(t['severity_calc']['factor_checks']['event_ids_confirmados'],[])
        self.assertIn('blocked_without_effect',
                      t['severity_calc']['factor_checks']['factores_descartados'])

    def test_vip_real_se_ajusta_con_directorio(self):
        alert=copy.deepcopy(self.alerta)
        alert['source_product']='EDR'
        alert['severity']='medium'
        alert['entities']={'users':[{'upn':'enric.bosch@tarvia.example'}], 'hosts':[]}
        t=self.evaluar(ticket(),alert)
        self.assertEqual(t['severity_calc']['criticitat']['nivel'],'Alta')
        self.assertEqual(t['severity'],'high')
        self.assertTrue(t['escalation']['escalate'])


if __name__=='__main__':
    unittest.main(verbosity=2)
