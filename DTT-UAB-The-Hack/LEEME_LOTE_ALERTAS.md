# Tarvia SOC — Analizar todas las alertas y crear 15 tickets

Dos programas independientes que **no cambian** `agente_soc_dcc.py` ni `dashboard_nivel2.py`.

## 1. Análisis determinista de TODO el dataset (sin LLM)

Coloca estos dos archivos al mismo nivel que `agente_soc_dcc.py` en `DTT-UAB-The-Hack`:

- `analizar_alertas.py`
- `generar_15_tickets.py`

Abre la terminal de Codespaces y ejecuta:

```bash
cd /workspaces/fallades/DTT-UAB-The-Hack
python analizar_alertas.py
```

Se crearán:

- `resultados/catalogo_alertas.csv`: una fila para **cada una de las 11.061 alertas**, fuente, regla, runbook, contexto CMDB explícito, severidad **base** cuando se conoce y pistas de correlación temporal (no confirmación de incidente).
- `resultados/resumen_dataset.json`: distribución y advertencias sobre límites.
- `resultados/seleccion_15.json`: 15 casos seleccionados de las **150 alertas de desarrollo**, con diversidad de fuentes/runbooks/severidades e incluyendo una alerta SCCM.

**Importante**: esta primera fase es una **preclasificación analítica**, no un triaje N1 con veredicto para las 11.061 alertas. No lee todos los logs ni aplica inteligencia externa. No inventa severidades finales ni cierra incidentes. Si no se conoce el activo afectado, deja la severidad base pendiente.

Para seleccionar de todo el dataset (no solo la muestra), opción alternativa:

```bash
python analizar_alertas.py --pool todas --limit-tickets 15
```

## 2. Probar los 15 casos antes de gastar llamadas LLM

Comprueba que la API SOC de Deloitte continúa arrancada en la otra terminal (8000) y que el secreto `DCC_API_KEY` está configurado en Codespaces. No lo copies al archivo.

```bash
python -m pip install openai-agents jsonschema requests
python generar_15_tickets.py --dry-run
```

## 3. Primera ejecución de 3 casos

```bash
python generar_15_tickets.py --limit 3
```

Se crearán hasta tres tickets en `resultados/tickets/`, cada uno validado contra `01_contexto/ticket_salida.schema.json`, y `resultados/metricas_tickets.csv` con éxito/error, tiempo y veredicto propuesto. La ejecución puede producir errores por modelo, herramientas o tiempo; se documentan por alerta y el lote continúa.

## 4. Completar 15 tickets

```bash
python generar_15_tickets.py --limit 15
```

**Se reanudará automáticamente**: los 3 tickets válidos de la ejecución anterior NO se recalculan. Para regenerar intencionadamente todos: `--force` (hace más llamadas).

La clave/modelo se pasan mediante variables de entorno sin mostrarlos en pantalla; predeterminado `ornith`. Para usar `nemotron`: `python generar_15_tickets.py --limit 15 --model nemotron`.

### Archivos resultantes

```text
resultados/
  catalogo_alertas.csv
  resumen_dataset.json
  seleccion_15.json
  metricas_tickets.csv
  tickets/
    ALR-XXXXXXXX-XXXXXX.json
  logs/
    ALR-XXXXXXXX-XXXXXX.log
  respaldo_ticket_original.json
```

**Precauciones**

- El agente actual escribe inicialmente en `ticket_generado.json`. El lote hace copia de seguridad y lo restaura al salir. **No ejecutar simultáneamente investigaciones desde el dashboard u otra terminal**, pues usan el mismo archivo temporal.
- No ejecutar varias instancias del lote a la vez.
- El programa solo llama al agente original que tiene herramientas GET; no ejecuta contención ni aprueba acciones.
- `valido_pendiente_revision` significa *JSON estructuralmente correcto*, no decisión de ciberseguridad demostrada. Revisar evidencias, cambios autorizados, severidad, agrupaciones, escalados y sesgos temporales.
- La muestra de 150 carece de reglas RB-08 y RB-10 y no contiene `critical`. Probarlos después con `--pool todas` y un lote separado para no sobrescribir la selección anterior.
- No hacer `git add .`. Los resultados, logs y cualquier secreto deben quedar fuera de commits automáticos. Idealmente agregad `resultados/` a `.gitignore` tras decidir qué métricas podéis compartir con los organizadores.
