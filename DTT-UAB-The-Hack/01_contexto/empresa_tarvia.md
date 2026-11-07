# Tarvia Group: ficha de la empresa

> Empresa ficticia creada para la hackathon. Cualquier parecido con una organización real es casual.

## Negocio
Tarvia es un retailer omnicanal de moda y hogar con sede en el 22@ de Barcelona. Factura unos 480 M€ al año, tiene 2.100 empleados
y 64 tiendas en España y Portugal (28 propias con red monitorizada por el SOC; el resto son franquicias). La venta online
(web y app) supone el 38% de la facturación y tiene 1,3 millones de clientes registrados. Los pedidos online salen del
centro logístico automatizado de Martorell, donde un clasificador controlado por PLC reparte los paquetes por transportista.

Desde junio, la web y la app incluyen «Vela», un asistente de compra basado en un modelo de lenguaje que puede consultar
pedidos del cliente autenticado, buscar productos e iniciar devoluciones.

## Lo que más le importa proteger
1. **La venta online**: cada hora de caída en campaña cuesta en torno a 120.000 € de venta.
2. **Los datos de clientes** (CRM y copias): una brecha es notificable a la AEPD y a la CNPD portuguesa en 72 horas.
3. **Los pagos**: tanto los cobros (PCI DSS) como los pagos a proveedores (fraude por cambio de IBAN).
4. **La salida de pedidos de Martorell**: si el clasificador se para, todos los pedidos online se retrasan.

## Calendario
El periodo del dataset (del 5 de octubre al 1 de noviembre de 2026) es la preparación de la campaña de Black Friday. Hay un pentest externo
de la tienda online contratado del 8 al 10 de octubre.

## Organización de seguridad
- CISO: Alba Rovira.
- SOC interno de 6 personas en horario 8:00-20:00 de lunes a viernes (3 N1, 2 N2, 1 responsable). Fuera de horario hay una
  guardia N2 localizable por teléfono; nadie mira la consola por la noche ni en fin de semana.
- Volumen: unas 4.000 alertas diarias antes de deduplicar; el dataset contiene una muestra deduplicada.

## Pila tecnológica (genérica)
| Capa | Herramienta | Fuente en el dataset |
|---|---|---|
| Identidad | IdP en la nube con MFA (push, TOTP, FIDO2) y directorio activo local | `idp_signins`, `idp_audit` |
| Acceso remoto | Concentrador VPN | `vpn` |
| Puesto y servidor | EDR en Windows y Linux | `edr_events` |
| Navegación | Proxy web seguro | `proxy`, `dns` |
| Red | Cortafuegos de nueva generación | `firewall` |
| Correo | Pasarela de correo con reescritura de enlaces | `email`, `email_clicks` |
| Web | WAF delante de la tienda online | `waf` |
| E-commerce | Logs de la aplicación | `ecom_auth`, `ecom_account` |
| Cloud | AWS (cuenta tarvia-prod, eu-west-1) | `cloudtrail` |
| Datos | DLP de correo y web; auditoría SQL del CRM | `dlp`, `sql_audit` |
| IA | AI Gateway del asistente Vela (guardarraíles y control de autorización de herramientas) | `ai_gateway` |
| Directorio activo | Eventos de seguridad de los controladores de dominio | `ad_events` |
| CI/CD | Logs de los pipelines de build y despliegue | `cicd_builds` |
| Correlación | SIEM | `03_alertas/alertas.jsonl` |

## Reglas internas que importan para el triaje
- Las cuentas `adm.*` solo pueden usarse desde `JUMP01`.
- La única herramienta de acceso remoto aprobada es TeamViewer Corporate gestionado por IT. AnyDesk no está aprobado.
- `svc_backup` está excluida de MFA por compatibilidad del agente de copias (riesgo aceptado en 2024).
- Solo `ENG-WS01` y `WMS01` pueden hablar con la red OT. Cualquier otro acceso necesita un cambio aprobado.
- El escáner `NESSUS01` escanea todas las redes salvo OT cada miércoles de 01:00 a 05:00.
- Los envíos de nóminas a la gestoría (`asesoria@gestoria-pons.example`) son un flujo aprobado.
- Terceros con acceso: Logisoft (proveedor del WMS) entra por VPN con la cuenta `ext.logisoft`, de lunes a viernes de 8 a 18 h, solo a WMS01.
- Los builds de la tienda online corren en `CI-RUNNER01` (AWS). Los paquetes internos se publican como `@tarvia/*` en un registro interno.
- Las tiendas tienen una red plana: el portátil del responsable y los TPV comparten segmento.
