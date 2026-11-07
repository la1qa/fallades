# Tarvia SOC — Un JSON completo por alerta

## Qué cambia

- `agente_soc_dcc_v2.py`: conserva el agente DCC que ya tenéis, pero admite `SOC_OUTPUT_PATH` para guardar **directamente** el resultado de cada alerta en su propio archivo. Añade caché de consultas de lectura idénticas, una instrucción para terminar cuando haya evidencia suficiente, y 24 turnos por defecto.
- `generar_15_tickets_v2.py`: investiga la selección que creó `analizar_alertas.py`; escribe archivos separados en `resultados/tickets/ALR-....json`; comprueba el esquema de Deloitte y campos esenciales de un ticket terminado. Reanuda sin rehacer tickets completos.

Un JSON puede ser **estructuralmente completo pero contener conclusiones incorrectas**. Revisad las evidencias de cada ticket antes de declararlo correcto. Los casos que no se completan van a `resultados/incompletos/` cuando exista un JSON parcial, y los errores al `resultados/logs/`. **Nunca se crean tickets ficticios de éxito.**

## Cómo instalar en Codespaces

1. Descargad los dos archivos `.py` de este paquete.
2. Subidlos a `DTT-UAB-The-Hack/`, **junto a** `agente_soc_dcc.py`, sin borrar el original.
3. Aseguraos de que Deloitte sigue levantado en otra terminal (en `06_herramientas`):

   ```bash
   uvicorn mock_soc_api:app --host 0.0.0.0 --port 8000
   ```

4. En otra terminal:

   ```bash
   cd /workspaces/fallades/DTT-UAB-The-Hack
   python -m pip install jsonschema openai-agents requests
   python analizar_alertas.py
   python generar_15_tickets_v2.py --dry-run
   python generar_15_tickets_v2.py --limit 1
   ```

5. Si el primero termina con `completo_pendiente_revision_humana`, probad los tres primeros y después los quince:

   ```bash
   python generar_15_tickets_v2.py --limit 3
   python generar_15_tickets_v2.py --limit 15
   ```

   Esta versión usa `ornith` y 24 turnos por defecto, con la variable `DCC_API_KEY` que ya está en Codespaces Secrets. No se debe pegar la clave en el código ni en GitHub.

## Estructura esperada

```text
DTT-UAB-The-Hack/
├── agente_soc_dcc.py                 # original (sin cambios)
├── agente_soc_dcc_v2.py              # agente actualizado
├── generar_15_tickets_v2.py         # nuevo generador
└── resultados/
    ├── seleccion_15.json
    ├── tickets/
    │   ├── ALR-20261007-011785.json
    │   ├── ALR-20261009-011791.json
    │   └── ... hasta 15 tickets completos
    ├── incompletos/
    ├── logs/
    ├── respaldo_tickets/
    └── metricas_tickets.csv
```

- Si el archivo `resultados/tickets/ALR-20261007-011785.json` que generó la versión anterior ya incluye todos los campos, se reutilizará **sin repetir llamadas** a la IA.
- Si le faltan datos importantes, se moverá a `resultados/incompletos/` y se volverá a investigar.
- El archivo histórico `ticket_generado.json` **no se toca** durante este lote.
- Para comprobar el estado del lote sin utilizar IA:

  ```bash
  python generar_15_tickets_v2.py --verify-only
  find resultados/tickets -maxdepth 1 -name 'ALR-*.json' | wc -l
  ```

- Para usar `nemotron` en vez de `ornith`:

  ```bash
  python generar_15_tickets_v2.py --limit 3 --model nemotron
  ```

- Para rehacer un ticket existente (se guarda una copia si era válido):

  ```bash
  python generar_15_tickets_v2.py --limit 1 --force
  ```

## Qué significa "completo"

Además de pasar `ticket_salida.schema.json`, cada archivo debe incluir: `ticket_id`, `alert_ids`, `title`, `verdict`, `confidence`, `severity`, `severity_rationale`, `affected`, `summary`, `evidence`, `enrichment`, `mitre`, `recommended_actions`, `escalation`, `open_questions`, `executed_actions` y `triage_seconds`.

Se exige al menos una evidencia con referencia y una recomendación concreta (cierre, escalado o más investigación). Cuando no se pueda concluir, el agente debe escribir `needs_more_info`, no inventar éxito ni compromiso. **No se ejecuta contención**.

## Seguridad y Git

Mantened los puertos 8000 y 8502 privados. Evitad subir secretos, `.env`, `resultados/logs/` y salidas de prueba al repositorio. Podéis guardar los scripts con:

```bash
git add agente_soc_dcc_v2.py generar_15_tickets_v2.py LEEME_TICKETS_JSON_COMPLETOS.md
git commit -m 'Guardar tickets SOC completos e independientes por alerta'
git pull --rebase origin main
git push origin main
```

Una validación de esquema no garantiza ausencia de falsos positivos; revisad el resultado con los runbooks y los logs reales.
