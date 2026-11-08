# Tarvia SOC · Entrega V3 · Nivel 1 y Nivel 2

**Modelo:** Ornith en GPUs DCC. **LLM_PROVIDER=dcc**, API compatible con OpenAI.
La API de *datos SOC* es distinta: se ejecuta localmente en el puerto 8000.
No se incluyen credenciales. No se ejecuta contención, ni real ni simulada, desde estos scripts.

> **Compatibilidad de esta entrega:** estos cinco archivos son complementos de
> `agente_soc_dcc_v3.py`, `severidad.py` y `correlacion_n2_v3.py`, que deben estar
> en la raíz de `DTT-UAB-The-Hack/`, junto con las carpetas de datos del reto.
> Los comandos que usan `procesar_lote_v3.py` o `dashboard_tickets.py` solo se
> pueden ejecutar si esos scripts también existen en el repositorio; no forman
> parte de este paquete de cinco archivos.

## 1. Qué archivos son los oficiales

| Etapa | Programa principal | Función |
|---|---|---|
| Preparar 15 casos | `analizar_alertas.py` | Selección diversa sobre la muestra; no da veredictos |
| Correlación preliminar | `analizar_agrupar_todas.py` | Analiza las 11.061 alertas, propone incidentes y campañas |
| Investigación N1 | `agente_soc_dcc_v3.py` | Agente Ornith, consultas de lectura y JSON por alerta |
| Política N1 | `politica_triaje_n1.py` + `severidad.py` | Verifica event_id, consulta CMDB, aplica matriz SOC y escalado |
| N2, validación | `correlacion_n2_v3.py` | Examina grupos, contrasta dos o más eventos, requiere causalidad confirmada por un analista |
| N2, ticket único | `consolidar_incidentes_n2.py` | Solo consolida grupos confirmados, sin modificar tickets N1 |
| Lote demo | `procesar_lote_v3.py` | Lanza Ornith por alerta, reanuda y guarda métricas/trazas |
| Dashboard | `dashboard_tickets.py` | Tickets V3 (prioritarios), V2 históricos, candidatos y grupos consolidados |
| Pruebas | `pruebas_politica_n1.py`, `pruebas_v3_limpia.py`, `comprobar_severidad_soc.py` | Comprobaciones offline: no necesitan GPU ni token |

Archivos redundantes/no activos: ver `90_archivo_no_activo/LEEME.md`.
No eliminar `01_contexto/`, `02_inventario/`, `03_alertas/`, `04_logs/`,
`05_inteligencia/` ni `06_herramientas/mock_soc_api.py`.

## 2. Arranque limpio en Codespaces

Abrir un terminal **en `DTT-UAB-The-Hack/`**:

```bash
python -m pip install -r requirements.txt
python comprobar_severidad_soc.py
python pruebas_politica_n1.py
python pruebas_v3_limpia.py
python analizar_agrupar_todas.py --actualizar
python procesar_lote_v3.py --dry-run --limit 5
```

Para iniciar el backend de datos SOC, usar **otro terminal** desde la raíz:

```bash
python -m uvicorn mock_soc_api:app --app-dir 06_herramientas --host 127.0.0.1 --port 8000
```

Visitar `http://127.0.0.1:8000/docs` o comprobar:

```bash
python agente_soc_dcc_v3.py ALR-20261005-000172 --check
```

Configurar `DCC_API_KEY` mediante los secretos del entorno Codespaces. **Nunca poner
la clave en el archivo, README, comando que se suba a Git ni salida JSON.**
La configuración por defecto de V3 usa
`DCC_BASE_URL=https://dcc-llm-gw.uab.cat/uabthehack/v1` y `DCC_MODEL=ornith`;
si los organizadores proporcionan otra URL o ruta, ajustar el secreto/variable
`DCC_BASE_URL`. No se ha comprobado la conexión DCC real sin credenciales.

Ejecutar una alerta, desde la raíz con la API SOC funcionando:

```bash
LLM_PROVIDER=dcc DCC_MODEL=ornith python -u agente_soc_dcc_v3.py ALR-20261005-000172
```

Procesar una selección de cinco (en serie, para no saturar Ornith):

```bash
python procesar_lote_v3.py --limit 5
python procesar_lote_v3.py --limit 15
python procesar_lote_v3.py --verify-only --limit 15
```

Para evaluar un conjunto propio:

```bash
python procesar_lote_v3.py --ids ALR-20261005-000172 ALR-20261005-000301
```

Cada alerta produce `resultados/v3/tickets/ALR-....json`, además de
`resultados/v3/auditorias/`, `resultados/v3/logs/` y `resultados/v3/metricas_v3.csv`.
Los V2 históricos de `resultados/tickets/` nunca se sobrescriben.

## 3. Nivel 2: de hipótesis a un ticket de incidente

```bash
python analizar_agrupar_todas.py --actualizar
python correlacion_n2_v3.py --alerta ALR-20261010-011797
```

Los grupos *candidatos* NO son incidentes confirmados. Para confirmar un grupo:
primero generar los tickets de **todas las alertas del grupo**, revisar el
origen, destino, usuario, horario y cadena causal, y anotar por lo menos dos
IDs de evento reales de **dos tickets diferentes**. Ejemplo orientativo
(**sustituir cada ID por valores reales del grupo y cada evento por sus pruebas**):

```bash
python correlacion_n2_v3.py --confirmar INC-ID_REAL \
  --analista "Analista N2" \
  --justificacion "Se comprobó la secuencia causal entre los eventos, con usuario, equipo, horario y efecto posterior coherentes." \
  --evento "ALR-ID_1=EVENTO-ID_1" \
  --evento "ALR-ID_2=EVENTO-ID_2"
python consolidar_incidentes_n2.py --all
python correlacion_n2_v3.py --reevaluar
```

La salida consolidada aparece en `resultados/v3/incidentes/INC-....json`.
Esta consolidación no inventa una cadena: preserva los eventos y agrupa
únicamente si la revisión humana continúa vigente. Al modificarse un ticket
se invalida automáticamente la confirmación previa y hay que revisar otra vez.

**Severidad oficial:** solo aplica matriz de política + máximo un nivel
por condiciones justificadas. El `+1 contextual N2` en auditorías es un
indicador interno del equipo, no modifica la severidad SOC oficial. Una campaña
masiva no justifica bajar automáticamente la severidad. Una coincidencia de IP
no demuestra que sea el mismo ataque.

## 4. Dashboard para la demo

En un tercer terminal:

```bash
python -m streamlit run dashboard_tickets.py
```

El panel muestra la cola de tickets existentes (V3 tiene prioridad sobre
V2), evidencias y contraste, propuesta de cierre/escalado, referencias a
correlación, grupos consolidados y trazas de las llamadas a herramientas.
No es una interfaz de ejecución de contenciones. Las alertas no investigadas
se contabilizan en el resumen global, pero no tienen aún un ticket detallado.

## 5. Limitaciones y criterios para la defensa

- Sin `DCC_API_KEY` no es posible verificar la ejecución real de Ornith;
  las pruebas locales usan un modelo simulado y la API SOC real del dataset.
- Confirmar un `event_id` **no equivale** a demostrar la interpretación del evento;
  el agente debe analizar su contenido, correlacionar y declarar incertidumbre.
- Un `benign_true_positive` debe fundamentarse en un cambio o en una excepción
  de política y en actor/origen/destino/horario. Para CHG, se comprueba que
  existe y cae en su ventana de cambio (Europe/Madrid). Verificar el **alcance**
  del cambio sigue requiriendo criterio analítico y revisión humana.
- El agrupador produce **propuestas**, no una reconstrucción completa del ataque.
  El ticket consolidado se crea tras revisión humana, no automáticamente.
- Los campos de ``severity_calc`` y ``verificacion_evidencias`` permiten auditar
  la diferencia entre lo propuesto por Ornith y la política aplicada por código.
- Ninguna función del flujo V3 hace POST a aprobaciones ni contención.
- `06_herramientas/refresh_iocs.py` es para los organizadores, no para el triaje;
  necesita ficheros adicionales no incluidos. **No ejecutarlo**.

### Demostración sugerida

Investigar una alerta WAF, una detección EDR y una alerta de identidad o VPN;
mostrar una autorización bien y otra mal justificada, comprobar el activo en
CMDB, la inteligencia y la evidencia exacta. Después enseñar 2 alertas
relacionadas, el candidato N2 y por qué solo se fusionan tras verificar la
causalidad. Los resultados del modelo son revisables, no verdades automáticas.
