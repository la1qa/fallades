# Política operativa del SOC de Tarvia

## 1. Qué hace el nivel 1
El N1 recibe cada alerta del SIEM y, en menos tiempo que su SLA, debe:
1. **Entender** qué ha detectado la regla y sobre qué entidades (usuario, equipo, IP, dominio, fichero).
2. **Contextualizar**: criticidad del activo, rol del usuario, cambios aprobados, viajes, historial.
3. **Enriquecer** los indicadores con inteligencia (TIP interno, OSINT, sandbox).
4. **Correlacionar** con otras alertas y logs de las mismas entidades (±24 h).
5. **Decidir el veredicto**: `true_positive`, `benign_true_positive` (la detección es correcta pero la actividad está autorizada) o `false_positive`.
6. **Asignar severidad final** con la matriz del apartado 2.
7. **Documentar** el ticket (formato en `ticket_salida.schema.json`) y **cerrar o escalar**.
8. **Proponer contención** cuando proceda. El N1 no ejecuta acciones disruptivas sin aprobación (apartado 4).

## 2. Matriz de severidad
Severidad final = cruce de la severidad de la regla con la criticidad del activo o identidad más crítica afectada.

| Regla \ Activo | Baja | Media | Alta | Crítica |
|---|---|---|---|---|
| informational | informational | informational | low | low |
| low | informational | low | low | medium |
| medium | low | medium | medium | high |
| high | medium | high | high | critical |
| critical | high | critical | critical | critical |

Ajustes (máximo un nivel arriba o abajo en total):
- **+1** si hay ejecución o acceso confirmado (no solo intento), si la identidad es VIP o privilegiada, o si hay datos personales o pagos implicados.
- **−1** si un control lo bloqueó antes de producir efecto y no hay actividad posterior.
- Una alerta asociada a un cambio aprobado o un flujo autorizado se clasifica como `benign_true_positive` con severidad `informational` o `low`.

## 3. SLA
| Severidad | Tiempo hasta triaje | Escalado | Notificación |
|---|---|---|---|
| critical | 15 min | Inmediato a N2 de guardia por teléfono | Responsable SOC y CISO |
| high | 30 min | A N2 en la misma jornada | Responsable SOC |
| medium | 4 h | Si tras el triaje hay indicios de compromiso | — |
| low | 24 h | No | — |
| informational | Revisión en lote diaria | No | — |

## 4. Acciones de contención y quién las aprueba
| Acción | Puede proponerla el N1 | Requiere aprobación de | Notas |
|---|---|---|---|
| Purgar un correo de todos los buzones | Sí, ejecutar | — | |
| Bloquear IOC (dominio, IP, hash) en proxy, correo y EDR | Sí, ejecutar | — | No bloquear servicios legítimos de uso dual (mega.nz, AnyDesk) a nivel global sin N2 |
| Revocar sesiones y forzar cambio de contraseña | Proponer | N2 | |
| Aislar un puesto de trabajo | Proponer | N2 | |
| Aislar un servidor | Proponer | N2 + responsable del servicio | Ver servicios_negocio.csv |
| Aislar TPV o frontales web | Proponer | N2 + negocio | Impacto en ventas |
| Deshabilitar cuenta de usuario o de servicio | Proponer | N2 | Una cuenta de servicio puede parar un proceso de negocio |
| Desactivar claves cloud | Proponer | N2 | |
| Cualquier acción sobre la red OT | Nunca | Responsable de Operaciones | Solo escalar |

## 5. Criterios de escalado obligatorio a N2
- Cualquier `true_positive` de severidad high o critical.
- Ejecución confirmada de código malicioso, robo de credenciales o persistencia.
- Datos personales de clientes o empleados que hayan podido salir de la organización (implica DPO).
- Fraude económico (pagos, IBAN, tarjetas regalo).
- Varias alertas que, juntas, describen una cadena de ataque aunque cada una por separado sea baja.

## 6. Agrupación
Varias alertas sobre la misma intrusión se documentan en **un único ticket** con todos los `alert_ids`.
Agrupar bien es parte del trabajo: diez tickets de un mismo incidente son diez veces más trabajo para el N2.
