"""Pruebas reproducibles: python -m unittest -v pruebas_nivel2.py"""
import unittest
from pathlib import Path
from nivel2_soc import MotorNivel2, autorizaciones, entidades, tipo_relacion, MATRIZ


class Nivel2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.motor = MotorNivel2(Path(__file__).resolve().parent)

    def test_dataset_real_primera_alerta_23_campana(self):
        r = self.motor.analizar("ALR-20261005-000172")
        self.assertEqual(r["correlacion"]["campana_similar"]["total"], 23)
        self.assertEqual(r["correlacion"]["mismo_incidente_candidato"]["total"], 0)
        self.assertEqual(r["severidad_politica"]["base"], "medium")
        self.assertEqual(r["autorizacion"]["candidatos"], [])

    def test_no_fusionar_por_ruta_distintos_atacantes(self):
        a = self.motor.by_id["ALR-20261005-000172"]
        b = self.motor.by_id["ALR-20261005-000157"]
        x, y = entidades(a), entidades(b)
        match = {k: list(x[k] & y[k]) for k in x.keys() & y.keys() if x[k] & y[k]}
        self.assertEqual(tipo_relacion(a, b, match), "campana_similar")

    def test_sccm_autorizacion_con_hora_y_padre(self):
        a = {"created_at":"2026-10-05T07:55:00Z", "rule_id":"UC-EDR-002",
             "entities": {"hosts": [{"hostname":"WS-BCN-1174", "ip":"10.10.1.13"}],
                         "processes": [{"name":"powershell.exe", "parent":"CcmExec.exe"}]}}
        v = autorizaciones(a, self.motor.changes)
        self.assertTrue(any(x["id"]=="CHG-2026-1031" for x in v["candidatos"]))
        a["created_at"] = "2026-10-05T14:55:00Z"
        self.assertFalse(autorizaciones(a, self.motor.changes)["candidatos"])

    def test_pentest_requiere_ip_destino_y_tiempo(self):
        a = {"created_at":"2026-10-09T10:00:00Z", "rule_id":"UC-WEB-001",
             "entities":{"ips":["192.0.2.10"], "urls":["https://www.tarvia.example/.env"]}}
        self.assertTrue(any(x["id"]=="CHG-2026-1042" for x in autorizaciones(a,self.motor.changes)["candidatos"]))
        a["entities"]["ips"]=["198.18.11.49"]
        self.assertFalse(autorizaciones(a,self.motor.changes)["candidatos"])

    def test_politica_matriz(self):
        self.assertEqual(MATRIZ["low"][3], "medium")
        self.assertEqual(MATRIZ["medium"][0], "low")
        self.assertEqual(MATRIZ["high"][3], "critical")

    def test_ticket_warning_delta_no_verificado(self):
        ticket={"severity":"low", "verdict":"true_positive", "escalation":{"escalate":False}}
        r = self.motor.analizar("ALR-20261005-000172", ticket)
        self.assertEqual(r["severidad_politica"]["base"], "medium")
        self.assertTrue(r["severidad_politica"]["avisos"])


if __name__ == "__main__":
    unittest.main()
