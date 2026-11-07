# Tarvia SOC — Primer módulo del nivel 2

## Qué hace

El módulo **nivel2_soc.py** analiza las 11.061 alertas del SIEM sin usar un LLM. Implementa:

1. Correlación de alertas dentro de ±24 horas mediante eventos compartidos, usuarios, equipos, clientes, IPs y rutas web.
2. **Separación explícita** entre duplicados, candidatos a un mismo incidente, otras relaciones y campañas similares. Coincidir en una ruta no basta para unir tickets.
3. Identificación **conservadora** de cambios autorizados: pentest de web, SCCM, escaneo NESSUS y flujo de nóminas cuando los campos de la alerta permiten verificar identidad/origen, alcance y horario. Las coincidencias requieren revisión humana antes de clasificar `benign_true_positive`.
4. Matriz de severidad exacta de `politica_soc.md`, con comprobación de activos del inventario y señalización de ajustes (+1/-1) que aún necesitan evidencia.
5. Revisión de diferencias entre ticket del LLM y severidad base calculada.

No ejecuta acciones disruptivas, no modifica la API, no genera verdicts automáticos ni modifica tickets originales.

## Instalación

Copiar **nivel2_soc.py**, **dashboard_nivel2.py** y **pruebas_nivel2.py** dentro de `DTT-UAB-The-Hack/`, al lado de `dashboard.py` y `agente_soc_dcc.py`.

## Probar sin modelo y sin API

Desde `DTT-UAB-The-Hack`:

```bash
python -m unittest -v pruebas_nivel2.py
python nivel2_soc.py ALR-20261005-000172 --ticket ticket_generado.json --output informe_nivel2.json
```

La alerta de prueba tiene otras **23 alertas con patrón web similar**, pero no se fusionan automáticamente.

## Abrir el dashboard ampliado

Mantener la API Deloitte arrancada en el puerto 8000. Desde una terminal nueva:

```bash
python -m pip install -r requirements_dashboard.txt
python -m streamlit run dashboard_nivel2.py --server.address 0.0.0.0 --server.port 8501
```

Abrir el puerto **8501** con visibilidad **Private**. La nueva pestaña **Nivel 2 · Correlación** enseña relaciones, autorizaciones candidatas y severidad base. Puede almacenar una evaluación humana local en `revisiones_nivel2/`. Sigue siendo necesario validar los tickets y evidencias manualmente.

## Límites importantes

- La **matriz base** se calcula automáticamente. El ajuste −1 por bloqueo solo procede si se ha comprobado que **no hay actividad posterior**; el módulo no inventa esa comprobación.
- El horario de `calendario_cambios.csv` **no declara la zona horaria**: se usa provisionalmente `Europe/Madrid`. Confirmar con Deloitte.
- Un activo web es un **destino potencial** si su web pública corresponde a `www.tarvia.example`; no se afirma que cada frontal haya recibido tráfico.
- No se comprueba toda la cadena de ataque: eso necesita nivel 3 y más fuentes.
- Para completar el nivel 2 de extremo a extremo, faltan correlación causal de casos complejos, agrupación consolidada con tickets N1 por alerta, y pruebas con diferentes runbooks.
- No subir secretos `DCC_API_KEY`, logs con información sensible ni resultados privados sin autorización.
