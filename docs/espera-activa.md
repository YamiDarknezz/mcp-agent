# Espera activa entre agentes

Cuando dos agentes se coordinan por Relay, un turno que termina "se duerme": nadie lo
despierta cuando la otra laptop responde. Si no hay notificaciones push (todavía no
existen), hace falta un mecanismo externo que vigile los canales y devuelva el control
al agente. Esto se llama **espera activa**.

El patrón probado usa las automatizaciones de OpenCode: un temporizador ejecuta código
sin modelo, consulta los mensajes cifrados con las herramientas del MCP `relay` y, si
hay algo nuevo, envía un prompt a la sesión que creó la automatización.

## Cuándo usarlo

- Hay una coordinación con otra laptop y se espera una respuesta, un PR o una confirmación.
- El agente termina su turno antes de que llegue la respuesta.
- No hay un humano disponible para escribir "continúa".

Cuándo **no** usarlo: tareas interactivas, tramitación de credenciales o cuando el
agente ya está trabajando: el prompt de la automatización entra en la conversación como
si fuera un mensaje del usuario y puede interrumpir lo que esté haciendo.

## Ejemplo

`channel_id`, `otro_dispositivo_id` y `account_id` son ejemplos; sustitúyelos por los
valores reales. El `account_id` se obtiene con `directory` o `my_identity`.

```js
const canales = [
  { id: "9875e240-8614-4703-8da6-5a18f68cef3e", after: 0 },
  { id: "99eb0169-e9a8-4b52-8568-56ef5e34d97f", after: 0 },
];
const otro = "3f584571-8b34-4a0c-892d-d130b7b231eb";
const s = input.state || { seqs: {}, lastNudge: 0, confirmed: false };

const res = await Promise.allSettled(
  canales.map((c) => tools.relay.read_messages({
    channel_id: c.id, after: s.seqs[c.id] ?? c.after, limit: 10,
  }))
);
const nuevos = [];
res.forEach((r, i) => {
  if (r.status !== "fulfilled" || !r.value.messages) return;
  const c = canales[i];
  for (const m of r.value.messages) {
    s.seqs[c.id] = Math.max(s.seqs[c.id] ?? c.after, m.seq);
    if (m.device_id === otro) nuevos.push(`[${c.id} seq ${m.seq}] ${m.content}`);
  }
});

if (nuevos.some((t) => /CONFIRMADO|PR listo/i.test(t))) s.confirmed = true;
if (s.confirmed && /CICLO_CERRADO/.test(nuevos.join("\n"))) {
  return { done: true, state: s, send: { prompt: "Ciclo cerrado; verifica y reporta." } };
}
if (nuevos.length) {
  return {
    state: s,
    send: {
      prompt: "Respuesta nueva en Relay. Continúa la coordinación, responde en el " +
        "canal correspondiente y no des el trabajo por terminado. Mensajes:\n" + nuevos.join("\n---\n"),
    },
  };
}
if (!s.confirmed && input.runs - s.lastNudge >= 4) {
  s.lastNudge = input.runs;
  return {
    state: s,
    send: {
      prompt: "Sin respuesta después de 4 minutos: envía un recordatorio al canal " +
        canales[1].id + " con relay.send_message y mención al account_id de la cuenta.",
    },
  };
}
return { state: s };
```

Crear la automatización (Code Mode de OpenCode):

```js
await tools.automation.create({
  name: "Relay - espera activa",
  trigger: { type: "every", every: "1 minute" },
  action: { type: "code", code: /* el código de arriba como string */ },
});
```

## Reglas importantes

1. **Guarda el cursor por canal en `state`.** Sin `seqs`, cada ejecución volvería a
   leer lo antiguo y se generarían prompts duplicados.
2. **Marcas de estado explícitas.** `confirmed`, `done` o `CICLO_CERRADO` evitan que un
   recordatorio obsoleto siga pidiendo una confirmación que ya llegó.
3. **Cooldown para recordatorios.** Un `lastNudge` con al menos 3–4 ejecuciones entre
   avisos evita llenar la conversación de mensajes repetidos.
4. **Texto dinámico.** No congeles el prompt del recordatorio: constrúyelo con el estado
   actual. En la práctica un texto fijo terminó pidiendo lo mismo después de resuelto.
5. **Borrar al terminar.** Usa `tools.automation.delete({ id })` o `done: true` en
   cuanto el ciclo se cierre; una espera activa sin dueño se vuelve ruido.
6. **Nada de secretos.** Ningún prompt debe contener códigos de alta, claves ni
   credenciales; Relay ya prohíbe pasarlos por herramientas.
7. **Frecuencia moderada.** Un minuto suele bastar; el buzón local de cada laptop ya
   sincroniza los canales seguidos, así que no hace falta sondear cada segundo.

## Relación con otras herramientas

- `channel_status` (issue #2) dice si el canal tiene clave local, suscripción y puente
  conectado; sirve para saber si la otra laptop puede ver el mensaje antes de insistir.
- `announce_channel` / `list_channel_announcements` (issue #4) permiten decir
  «conectate al canal X» sin pasar UUIDs a mano y sin conceder acceso.
- `directory` (issue #1) entrega el `account_id` para las menciones que disparan avisos
  cuando la suscripción está en modo `mentions`.

Si el runtime dispone de un MCP de espera por condición (`wait_for_file`, `wait_for_log`,
`wait_for_process`, `wait_for_port`, `wait_cmd`), prefiérelo sobre una automatización de
sondeo: evita los prompts inyectados y no interrumpe la sesión.
