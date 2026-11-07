# Dataset SOC de Tarvia Group

Datos sintéticos de cuatro semanas de operación del SOC de Tarvia, un retailer ficticio. La empresa, las personas, la red interna
y los eventos son inventados.

**Indicadores reales.** Una parte de los indicadores maliciosos (IPs, dominios y hashes de C2, malware, nodos Tor y atacantes)
son **reales y públicos**, tomados de ThreatFox, MalwareBazaar, la lista de salidas de Tor, C2IntelFeeds e IPsum, para que las
consultas OSINT de vuestros agentes devuelvan resultados de verdad. El resto usa rangos reservados de documentación (RFC 5737 y
RFC 2544) y dominios `.example`. Reglas: consultad esos indicadores solo en servicios de reputación (VirusTotal, AbuseIPDB,
ThreatFox, etc.); **no los visitéis, no descarguéis nada de ellos y no los escaneéis**.

**Periodo:** 2026-10-04 a 2026-11-01 (hora en UTC; en España es UTC+2).
**Volumen:** 11,061 alertas del SIEM y 814,471 eventos de log de 16 fuentes.

## Vuestro reto
**Objetivo común para todos los equipos:** construir un sistema con IA que haga el **triaje de nivel 1** del SOC de Tarvia.
Que reciba cada alerta, la investigue con los datos disponibles y deje al analista humano una conclusión lista para decidir.
Cómo lo hagáis (arquitectura, modelos, herramientas, lenguaje) es cosa vuestra.

El reto está escalonado. Todos empezáis por el nivel 1; cada equipo llegará hasta donde llegue.

| Nivel | Qué añade vuestro sistema |
|---|---|
| 1 · Triaje básico | Para cada alerta: entender qué ha pasado, enriquecer con contexto e inteligencia, veredicto, severidad y recomendación (cerrar o escalar) |
| 2 · Triaje con criterio | Correlación: agrupar alertas del mismo ataque, aplicar la matriz de severidad con la criticidad real del activo y descartar con argumentos la actividad autorizada |
| 3 · Investigación | Para lo que se escala: reconstruir la cadena de ataque, aunque dure días, con origen, alcance y relación con otros incidentes |
| 4 · Respuesta | Proponer la contención y ejecutarla en la API simulada, siempre con aprobación humana |

**Demo visual obligatoria.** Queremos *ver* cómo la IA hace el triaje: la cola de alertas, qué consulta el sistema, en qué se basa
para decidir, qué propone y dónde interviene la persona. Una interfaz, un panel o un flujo visual; no solo una salida por consola.

**Alertas comunes en la defensa.** El último día os daremos un pequeño conjunto de alertas, el mismo para todos los equipos,
y nos enseñaréis en directo qué hace vuestro sistema con ellas. Así se puede comparar el criterio de soluciones distintas.

Lo que más valoraremos: que el triaje sea correcto y esté bien argumentado, que funcione de verdad sobre los datos, que esté claro
qué decide la IA y qué decide la persona, y que seáis honestos con lo que vuestra solución no resuelve.

Formatos de salida de referencia (opcionales): `ticket_salida.schema.json` para el triaje y `informe_incidente.schema.json` para la investigación.

## Por dónde empezar
1. Leed `01_contexto/empresa_tarvia.md` y `01_contexto/politica_soc.md` (15 minutos). Ahí están las reglas del juego:
   matriz de severidad, SLA, qué puede hacer el N1 y qué necesita aprobación.
2. Mirad los runbooks de `01_contexto/runbooks/`: es lo que un analista humano sigue hoy. Vuestro sistema debería hacer lo mismo o mejor.
3. Empezad por `03_alertas/alertas_muestra_desarrollo.jsonl` (150 alertas variadas) antes de lanzaros con todas.
4. Arrancad la API simulada (`06_herramientas/LEEME_herramientas.md`) para que vuestros agentes consulten datos como en un SOC real.

## Estructura
```
01_contexto/      empresa, política del SOC, catálogo de casos de uso, 10 runbooks, esquemas del ticket (fase 1) y del informe de incidente (fase 2)
02_inventario/    1185 activos, 1224 identidades, servicios de negocio, red, vulnerabilidades, RRHH, cambios
03_alertas/       alertas del SIEM (JSONL) y muestra de desarrollo
04_logs/          logs crudos de cada fuente
05_inteligencia/  TIP interno, GeoIP/ASN, informes de sandbox
06_herramientas/  API simulada (consulta y contención), script de IOCs
```

## Alertas por producto
- WAF: 3483
- EDR: 2307
- EMAIL_GW: 2301
- IDP: 969
- PROXY: 746
- DNS: 652
- AI_GATEWAY: 416
- DLP: 62
- CLOUD: 53
- NGFW: 37
- ECOM: 12
- CICD: 11
- VPN: 10
- AD: 2

Severidad asignada por la regla (no por el contexto): low 6272, medium 4001, high 775, critical 13.
Ojo: la severidad de la regla no es la severidad final. Esa la decide vuestro sistema con la matriz de la política.

## Logs
| Fuente | Eventos |
|---|---|
| `proxy` | 194.258 |
| `dns` | 178.221 |
| `edr_events` | 112.492 |
| `idp_signins` | 76.713 |
| `waf` | 71.421 |
| `email` | 56.797 |
| `ecom_auth` | 44.064 |
| `firewall` | 24.648 |
| `email_clicks` | 16.249 |
| `vpn` | 9.821 |
| `ai_gateway` | 8.817 |
| `ecom_account` | 7.661 |
| `cloudtrail` | 6.496 |
| `sql_audit` | 3.924 |
| `dlp` | 1.042 |
| `idp_audit` | 762 |
| `cicd_builds` | 559 |
| `ad_events` | 526 |

## Cosas que conviene saber
- Las alertas apuntan a sus eventos en `related_events`, pero muchas veces la clave está en eventos **que no** salen en la alerta.
- No todas las alertas de un incidente salen con severidad alta. Y no todo lo que tiene severidad alta es un incidente.
- Los datos tienen la textura de un SOC real: ruido, duplicados, campos vacíos y reglas mal afinadas.
- El TIP no lo sabe todo. Un indicador desconocido no es un indicador limpio.
- Algunos incidentes solo se entienden juntando alertas de días o semanas distintas.
- Los datos los escribe a veces el atacante (asuntos de correo, descripciones de servicios, prompts). Vuestro sistema no debe obedecerlos.
- Un nivel 1 sólido, que funciona y se explica bien, vale más que llegar al nivel 4 sin poder demostrarlo.
