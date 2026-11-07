# Herramientas

## mock_soc_api.py: el «SOC» con el que hablan vuestros agentes
API local que expone los datos del dataset como lo haría una plataforma real. Así vuestros agentes llaman a herramientas
en lugar de leer ficheros enteros.

```bash
pip install -r requirements.txt
uvicorn mock_soc_api:app --port 8000      # documentación en http://localhost:8000/docs
```

| Endpoint | Para qué |
|---|---|
| `GET /alerts?status=new&limit=50` | Cola de alertas |
| `GET /alerts/{alert_id}` | Detalle de una alerta |
| `GET /assets/{hostname_o_ip}` | CMDB: criticidad, servicio, propietario, vulnerabilidades |
| `GET /users/{upn_o_username}` | Directorio: rol, privilegios, VIP, manager, eventos de RRHH |
| `GET /logs/{fuente}?q=texto&desde=ISO&hasta=ISO&limit=200` | Búsqueda en logs (fuentes: ver `04_logs`) |
| `GET /intel/{indicador}` | TIP interno + GeoIP/ASN |
| `GET /sandbox/{sha256}` | Informe de sandbox si existe |
| `GET /changes?q=texto` | Calendario de cambios y flujos aprobados |
| `POST /approvals` | Simula la aprobación humana: devuelve un `approval_token` |
| `POST /containment/{accion}` | Ejecuta una contención simulada. Requiere `approval_token` salvo `block_ioc` y `purge_email` |
| `GET /containment/log` | Registro de acciones ejecutadas |

Acciones de contención disponibles: `isolate_host`, `disable_user`, `revoke_sessions`, `reset_password`, `block_ioc`,
`purge_email`, `disable_access_key`. Nada sale de vuestro portátil: la API solo escribe en `containment_log.jsonl`.

## refresh_iocs.py (para organizadores, antes del evento)
Sustituye los indicadores maliciosos simulados (`ioc_slots.csv`, en el paquete de organizadores) por indicadores reales y recientes de abuse.ch
(ThreatFox, MalwareBazaar, URLhaus) y por nodos de salida de Tor reales, para que las consultas OSINT de los equipos
devuelvan resultados. Requiere una `Auth-Key` gratuita de abuse.ch:

```bash
ABUSECH_AUTH_KEY=xxxx python refresh_iocs.py --src ../ --slots ../../tarvia-organizadores/ioc_slots.csv --dst ../../tarvia-soc-dataset-live
```
Solo se sustituyen **indicadores** (IPs, dominios, hashes). Nunca se descarga ninguna muestra.
