"""Pruebas de regresión de severidad.py para el SOC de Tarvia.

Uso: python comprobar_severidad_soc.py
Solo importa severidad.py y hace cálculos locales; no llama a Deloitte ni a ornith,
no modifica archivos y sale con código != 0 si encuentra errores.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

try:
    import severidad
except ImportError as exc:
    raise SystemExit(
        "ERROR: Falta severidad.py en esta carpeta. Coloca ambos archivos "
        "junto a agente_soc_dcc_v2.py antes de ejecutar la comprobación."
    ) from exc


class PruebasSeveridadSOC(unittest.TestCase):
    def calcular(self, regla, criticidad, factores, **kwargs):
        nivel, razon = severidad.severidad_final(
            regla, criticidad, factores, **kwargs
        )
        self.assertIsInstance(razon, str)
        self.assertTrue(razon.strip(), "La justificación no puede estar vacía")
        return nivel, razon

    def test_matriz_sin_ajustes(self):
        casos = [
            ("low", "Media", "low"),
            ("low", "Crítica", "medium"),
            ("medium", "Media", "medium"),
            ("high", "Alta", "high"),
        ]
        for regla, criticidad, esperado in casos:
            with self.subTest(regla=regla, criticidad=criticidad):
                obtenido, _ = self.calcular(regla, criticidad, {})
                self.assertEqual(obtenido, esperado)

    def test_correlacion_confirmada_aplica_plus_uno(self):
        nivel, razon = self.calcular(
            "low", "Media", {"correlation": "chain"},
            n_alertas=3, n_reglas=2, fuentes=2,
        )
        self.assertEqual(nivel, "medium")
        self.assertIn("+1", razon)

    def test_correlacion_no_confirmada_no_sube(self):
        # Una sola alerta, una sola regla, o una única fuente: insuficiente.
        for detalles in [
            {"n_alertas": 1, "n_reglas": 2, "fuentes": 2},
            {"n_alertas": 3, "n_reglas": 1, "fuentes": 2},
            {"n_alertas": 3, "n_reglas": 2, "fuentes": 1},
        ]:
            with self.subTest(**detalles):
                nivel, _ = self.calcular(
                    "low", "Media", {"correlation": "chain"}, **detalles
                )
                self.assertEqual(nivel, "low")

    def test_patron_benigno_jamas_resta_por_correlacion(self):
        # Importante: se prueban muchos tamaños, usuarios, días y reputaciones.
        for n in (3, 50, 9000):
            for reputacion in ("benign", "malicious", None):
                patron = {
                    "indicador": "192.0.2.10",
                    "n_alertas": n,
                    "n_usuarios": 100,
                    "n_dias": 30,
                    "en_cadena": False,
                }
                def consulta(_path, **_kwargs):
                    return {"tip": {"reputation": reputacion}}
                with self.subTest(n=n, reputacion=reputacion):
                    nivel, _ = self.calcular(
                        "medium", "Media", {"correlation": "benign_pattern"},
                        n_alertas=n, n_reglas=3, fuentes=2,
                        patron=patron, get=consulta,
                    )
                    self.assertEqual(nivel, "medium")

    def test_bloqueo_oficial_si_permite_minus_uno(self):
        nivel, _ = self.calcular(
            "medium", "Media", {"blocked_without_effect": True}
        )
        self.assertEqual(nivel, "low")

    def test_patron_y_bloqueo_aplican_solo_minus_uno_oficial(self):
        nivel, _ = self.calcular(
            "medium", "Media",
            {"blocked_without_effect": True, "correlation": "benign_pattern"},
            n_alertas=200, n_reglas=2, fuentes=2,
            patron={"n_alertas": 200, "n_usuarios": 80, "n_dias": 15},
        )
        self.assertEqual(nivel, "low")

    def test_ajustes_soci_no_se_acumulan_entre_si(self):
        nivel, _ = self.calcular(
            "medium", "Media",
            {
                "confirmed_execution_or_access": True,
                "vip_or_privileged_identity": True,
                "personal_or_payment_data": True,
            },
        )
        self.assertEqual(nivel, "high")

    def test_plus_extra_de_correlacion_documentado_como_adaptacion(self):
        # Decisión del equipo: +1 SOC +1 correlación => dos niveles.
        # NO es la severidad oficial permitida por Deloitte.
        nivel, razon = self.calcular(
            "medium", "Media",
            {"confirmed_execution_or_access": True, "correlation": "chain"},
            n_alertas=3, n_reglas=2, fuentes=2,
        )
        self.assertEqual(nivel, "critical")
        self.assertIn("fora del límit de la política", razon)

    def test_benigno_autorizado_sigue_limitado_a_low(self):
        nivel, _ = self.calcular(
            "high", "Crítica", {}, veredicto="benign_true_positive"
        )
        self.assertEqual(nivel, "low")


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(PruebasSeveridadSOC)
    resultado = unittest.TextTestRunner(verbosity=2).run(suite)
    if resultado.wasSuccessful():
        print("\nOK: +1 por cadena; 0 por patrón benigno; -1 solo por bloqueo oficial.")
        print("AVISO: el +1 extra por correlación es una adaptación del equipo, NO de Deloitte.")
        print("AVISO: verifica por separado que el agente principal importe severidad.py.")
    sys.exit(0 if resultado.wasSuccessful() else 1)
