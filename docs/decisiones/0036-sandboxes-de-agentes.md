# 0036 · Sandboxes de agentes: un proxy propio pone las credenciales y el sandbox solo lleva una credencial suya

- Estado: aceptado (Omar lo aceptó el 2026-11-06 con las recomendaciones de las tres preguntas finales; ver «Respuesta de Omar», punto 11)
- Fecha: 2026-11-06
- Enmienda: 2026-11-09, **aceptada** (ver «Enmienda del 2026-11-09»): la parte de los sandboxes en la skill, y «Sandboxes activos» en las apps de Mac e iOS, con la lista sacada de la bitácora y la revocación firmada por la cuenta que el servidor aplica en la llamada siguiente. Omar decidió que revocar no pide Face ID ni Touch ID, y el mismo día respondió P1–P6 con la opción recomendada de cada una (E9). Tras la revisión de la enmienda, también el mismo día, respondió Q-C y Q-D, y P6 quedó aclarado (E9). La llave de un elemento compartida pasa al tipo `0x23` (E10)

## Contexto

### Cómo trabaja Omar hoy
- Usa su propia versión de **T3 Code**, una interfaz para agentes de programación (Claude Code, Codex…) que abre un *worktree* por conversación. T3 Code corre en su Mac, pero Omar empieza muchas conversaciones desde el teléfono.
- Cada conversación nace dentro de un **sandbox**: una máquina virtual Linux desechable de Boat (boat.dev), donde el agente tiene terminal, red y los CLIs del proyecto.
- Para que el agente pueda desplegar, T3 Code le pasa un token de Northflank, el mismo para todos, en una variable de entorno. Lo recibe el *setup script*, el script que Boat corre en cada arranque del sandbox. El script corre `northflank login -t …`, que guarda el token en `~/.northflank`, y después borra la variable.
- Dentro del sandbox se usan, entre otras herramientas, la CLI de Northflank, la CLI de Railway y Maple como servidor MCP.

### Lo que falla
1. **Todos los sandboxes reciben el mismo token.** Si uno se filtra, no se sabe por cuál sandbox salió, y revocarlo los rompe todos.
2. **El token vive más que el sandbox.** Es de larga duración y no muere al borrar la conversación.
3. **El token real está dentro del sandbox:** en disco (`~/.northflank`) y, durante el arranque, en el entorno. Lo puede leer el agente, cualquier programa que corra ahí y quien copie el disco. Boat, además, guarda las variables de cada sandbox.
4. **Nadie registra qué hizo cada sandbox con el token,** y nadie puede pedir permiso antes de algo peligroso, como borrar un servicio.
5. **Los archivos `.env` acaban en los *worktrees*,** con valores en claro.

> **Aviso de seguridad de Northflank.** El 2026-11-06, la página de sandboxes de Northflank (<https://northflank.com/product/sandboxes>) mostraba un aviso de incidente de seguridad que pedía a los usuarios rotar todas las credenciales definidas por ellos.

### Lo que Klav tiene hoy y por qué no basta
- **Un agente** es una identidad propia (X25519 + Ed25519) con un *grant*: un documento firmado por la cuenta con la política y las llaves de los proyectos que puede abrir. Cada petición del agente va firmada; no existe un token de portador (ADR [0014](0014-agentes-fase-4.md) §3). Un **token de portador** (*bearer*) es una credencial que basta con mostrar: quien la copia, la usa.
- **Dar a cada sandbox su propio agente** pondría una llave de Klav dentro del sandbox. Quien copiara el sandbox se llevaría una llave que descifra todo lo que cubre el grant. Además, `run` e `inject` ponen el valor en el entorno del proceso, donde el agente lo puede leer (riesgo residual 31). Omar lo prohíbe (respuesta 3).
- **`klav agent run` no sirve para un servidor MCP por stdio** (un MCP que habla JSON-RPC por la entrada y la salida estándar): cierra la entrada, captura la salida hasta 64 KiB, la redacta, la devuelve al terminar y mata el proceso a los 10 minutos (`crates/klav-sdk/src/actions.rs`).
- El encargo original pedía un solo comando y reutilizar agentes y grants, sin un modelo paralelo (ADR [0032](0032-entornos-por-repositorio.md) §4). Este ADR lo cumple: el proxy y quien crea los sandboxes son agentes, y un sandbox no es una identidad nueva sino una credencial corta del proxy.

## Lo investigado

### Boat (<https://docs.boat.dev>)
- Son máquinas virtuales Linux completas, con Docker y systemd. La API (`https://boat.dev/api/v1`) crea un sandbox con `POST /sandboxes`, que acepta `ttlSeconds` y variables propias del sandbox (`env`, hasta 100 variables y 64 KB). Boat guarda esas variables.
- Cada repositorio tiene su *setup script*, que corre **en cada arranque**. Las credenciales de IA se escriben en `/run/ascii-secrets/env.sh`, que solo leen las *shells* de inicio de sesión.
- **Red:** una IPv6 pública por sandbox y salida por IPv4. Algunos sandboxes no tienen IPv4 propia, y la IP cambia al reanudar, así que fijar por IP no sirve.
- **Sin control de salida:** «boat has no API setting for network rules». El código del sandbox puede ignorar la configuración de proxy o quitar reglas del cortafuegos.
- Se detiene solo a la hora de crearlo o reanudarlo, sin temporizador de inactividad. **No hay webhook de borrado:** quien borra el sandbox tiene que avisar.
- Dentro del sandbox, `ASCII_TOKEN` y la llave de la API solo valen para ese mismo sandbox. No hay identidad de carga de trabajo (OIDC) que el sandbox pueda presentar a otro servicio.
- Boat ofrece su propio proxy de credenciales («placeholder keys, boat adds the real key»), documentado para las credenciales de IA, a 1 USD al día. Sus páginas comerciales hablan de un «secret proxy for any HTTPS API» (sin confirmar en la documentación).

### Cómo llega el tráfico de cada herramienta a un proxy
Hay tres modos:

- **(a) URL base:** la herramienta deja cambiar la dirección de la API.
- **(b) `HTTPS_PROXY` con una CA de confianza:** la herramienta manda todo por un proxy HTTP, que abre el TLS. Una **CA** (autoridad de certificación) es la llave que firma certificados; si el sandbox confía en una CA propia, el proxy puede presentarse como `api.railway.com`. Esto es **interceptar TLS**.
- **(c) MCP remoto:** el cliente MCP apunta a una URL, y el proxy añade la cabecera de autenticación.

| Herramienta | Modo | Detalle |
|---|---|---|
| CLI de Northflank (Node, `@northflank/cli`) | (a) | `northflank login -n NOMBRE -t TOKEN --host HOST` guarda un *host* por contexto. Sale en la referencia de Fig (<https://fig.io/manual/northflank/login>), no en la documentación oficial (sin confirmar; comprobar con `northflank login --help`). Configuración en `~/.northflank/config.json` o en `NF_CONFIG_DIR` |
| CLI de Railway (Rust, `reqwest` con `rustls` y las raíces del sistema) | (b) | No deja cambiar la URL en las versiones publicadas: `RAILWAY_BACKBOARD_URL` solo existe con `#[cfg(debug_assertions)]`, y el comentario del código dice que hacerlo en un binario publicado «would let a hostile environment redirect authenticated traffic» (`src/config.rs` en <https://github.com/railwayapp/cli>). `reqwest` respeta `HTTPS_PROXY`, y las raíces del sistema leen `SSL_CERT_FILE`. Tokens: `RAILWAY_TOKEN` (de proyecto, cabecera `Project-Access-Token`) y `RAILWAY_API_TOKEN` |
| Maple | (c) | El MCP vive en `https://api.maple.dev/mcp` (y `api.eu.maple.dev`), por *Streamable HTTP*, con `Authorization: Bearer maple_ak_…` u OAuth 2.1 (<https://maple.dev/docs/reference/authentication/>). El `url` del cliente MCP se puede cambiar |

**Node** solo respeta `HTTPS_PROXY` con `NODE_USE_ENV_PROXY=1` o `--use-env-proxy`: en `fetch` desde la v22.21.0 o la v24.0.0, y en `node:http` y `https` desde la v22.21.0 o la v24.5.0. La CA extra va en `NODE_EXTRA_CA_CERTS`, que la añade a las del sistema. Un `net.Socket` directo se salta el proxy (<https://nodejs.org/learn/http/enterprise-network-configuration>). Otros programas usan `SSL_CERT_FILE` (que reemplaza las raíces), `REQUESTS_CA_BUNDLE` o `CURL_CA_BUNDLE`.

### Proxies que ponen credenciales y se alojan uno mismo
Un **proxy que pone credenciales** (*credential-injecting proxy*) recibe la petición sin el secreto, añade el secreto real y la reenvía. Quien hace la petición nunca lo tiene.

- **Fly.io `tokenizer`** (<https://github.com/superfly/tokenizer>):
  - el cliente lleva el secreto **sellado** con la llave pública del proxy (caja sellada de NaCl) en la cabecera `Proxy-Tokenizer`;
  - se autentica con `Proxy-Authorization: Bearer`, comparado contra un resumen SHA-256, o con una prueba de que la petición viene de cierta máquina de Fly;
  - el secreto lleva `allowed_hosts`, para que un cliente comprometido no lo mande a un servicio que lo devuelva;
  - el proxy no guarda estado. El cliente le habla por HTTP sin cifrar dentro de una VPN.
- **CyberArk Secretless Broker** (<https://github.com/cyberark/secretless-broker>, <https://docs.cyberark.com/secrets-manager-sh/13.2/en/content/overview/scl_how_it_works.htm>):
  - un proxy local junto a la aplicación, con un conector por protocolo y plantillas de cabeceras para HTTP;
  - **no autentica al cliente, a propósito:** cualquiera que llegue al puerto recibe una sesión autenticada.
- **Envoy `credential_injector`** (<https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/credential_injector_filter>): pone una cabecera Basic o Bearer, o hace OAuth2 *client credentials*. La propia documentación dice que lleva poco tiempo en producción.
- **iron-proxy**, en Hermes Agent (<https://hermes-agent.nousresearch.com/docs/user-guide/egress/iron-proxy>):
  - tokens de mentira (*placeholders*) en el sandbox e interceptación TLS con una CA propia montada en solo lectura;
  - una lista de hosts permitidos que responde `403`, y rangos prohibidos (*loopback*, metadatos de la nube, redes privadas) comprobados al conectar, contra el *DNS rebinding*;
  - documenta cómo se lo saltan: sockets directos, firmas SigV4, archivos montados y exfiltración hacia hosts permitidos.
- **Infisical Agent Vault** (<https://github.com/Infisical/agent-vault>, <https://infisical.com/docs/documentation/platform/agent-vault/why-agent-vault>): un proxy `HTTPS_PROXY` que intercepta TLS, con sesiones que solo permiten un conjunto de accesos hasta que vencen o se revocan. Recomienda desplegarlo en otro host que los agentes.
- **Otros:**
  - Cloudflare Sandbox: un Worker que valida un JWT corto (<https://developers.cloudflare.com/sandbox/guides/proxy-requests>).
  - LangSmith Auth Proxy: reglas por host y credenciales dinámicas (<https://www.langchain.com/blog/how-auth-proxy-secures-network-access-for-langsmith-agent-sandboxes>).
  - NVIDIA OpenShell: liga cada credencial a host, puerto y ruta (<https://docs.nvidia.com/openshell/sandboxes/manage-providers.md>).
  - AIWG: hosts, prefijos de ruta, métodos, límites de ritmo y redacción del secreto en la respuesta (<https://docs.aiwg.io/agentic-sandbox/pages/security--credential-proxy.html>).
  - StackOne: un proxy esconde la llave pero no limita lo que hace con ella, por eso importan las listas de rutas y métodos (<https://www.stackone.com/blog/ai-agent-sandbox-api-keys/>).
  - AgentPatterns, con un ejemplo en Caddy (<https://agentpatterns.ai/security/scoped-credentials-proxy/>).
  - Omnigent (<https://github.com/omnigent-ai/omnigent/blob/main/designs/SANDBOX_CREDENTIAL_PROXY.md>).
  - Blaxel (<https://blaxel.ai/blog/egress-proxy-api-credentials-ai-agent-sandboxes>).
  - William Zujkowski (<https://williamzujkowski.github.io/posts/2026-07-02-agentic-ai-sandbox-secret-proxying-gap/>).
- **Northflank** ofrece en sus propios sandboxes secretos en la salida, sin que el valor entre, e identidad de carga de trabajo con tokens cortos (<https://northflank.com/product/sandboxes>).

### Proxies alojados por un tercero, y cómo piden confianza
- **Nango** (<https://nango.dev/docs/reference/api/proxy/get>, <https://nango.dev/platform/request-proxy>): se llama a `https://api.nango.dev/proxy/{ruta}` con la llave de Nango y un `Connection-Id`, y Nango añade la credencial del proveedor. Dice que guarda los tokens cifrados y que en sus registros guarda método, URL, estado y cabeceras, nunca los cuerpos. **Hay que creerle a Nango.**
- **VGS**, *Outbound Routes* (<https://docs.verygoodsecurity.com/vault/http-proxy/outbound-connection>): un proxy `HTTPS_PROXY` con usuario y contraseña de proxy y un certificado propio, que cambia alias por valores reales de tarjetas en la salida. La confianza descansa en la empresa y en su cumplimiento de PCI.
- **Cloudflare AI Gateway con *BYOK*** (<https://developers.cloudflare.com/ai-gateway/configuration/bring-your-own-keys/>): guarda las llaves del proveedor de IA en su *Secrets Store* y las pone en cada petición. Hay que creerle a Cloudflare.
- **Evervault Relay** (<https://evervault.com/blog/how-we-built-relay>, <https://evervault.com/blog/e3>): es el único de la lista que no pide confianza en la empresa. Descifra dentro de su motor E3, que corre en AWS Nitro Enclaves, y pone el valor en la petición HTTPS de salida. La llave maestra está repartida con Shamir. Su producto *Enclaves* expone documentos de atestación para que el cliente compruebe qué código corre.
- **El proxy de Boat** y el de **Northflank** piden creer en el proveedor del sandbox.

**Conclusión:** los servicios alojados piden creer en la empresa, con su cumplimiento normativo como garantía. Solo Evervault cambia esa confianza por hardware y código verificable.

### Cómo llegar a un Mac detrás de NAT
Solo hace falta para el proxy en el Mac (§1). Un proxy en un servidor tiene dirección pública.

- **Tailscale** (<https://tailscale.com/kb/1085/auth-keys>, <https://tailscale.com/kb/1111/ephemeral-nodes>):
  - una **llave de autenticación** (*auth key*) une una máquina a la red privada. Puede ser:
    - de un solo uso, que se revoca sola al usarse;
    - efímera, para que el nodo desaparezca de 30 a 60 minutos después de quedar desconectado, o enseguida con `tailscale logout` o `--state=mem:`;
    - preaprobada;
    - con etiquetas (*tags*) que deciden a qué puede llegar.
  - Vence en 1 a 90 días y se puede crear por la API con un cliente OAuth.
  - **Revocar la llave no saca a los nodos que ya entraron.**
- **Cloudflare Tunnel** descifra el TLS en el borde de Cloudflare para dar sus funciones de WAF y caché. Lo dicen terceros (<https://pluggie.io/blog/cloudflare-tunnel-tls-privacy>); no está confirmado en la documentación de Cloudflare. Para TCP arbitrario hace falta `cloudflared` también en el cliente, con un inicio de sesión de Access (<https://developers.cloudflare.com/cloudflare-one/access-controls/applications/non-http/cloudflared-authentication/arbitrary-tcp/>).
- **ngrok** permite *endpoints* TLS que su nube no descifra, terminados en el agente o en el servicio, si uno gestiona sus certificados (<https://ngrok.com/docs/universal-gateway/tls-termination>).
- **Railway**:
  - su borde descifra el TLS de los dominios HTTP públicos y reenvía la petición (<https://docs.railway.com/networking/edge-networking>);
  - su *TCP Proxy* reenvía TCP en la capa 4 (<https://docs.railway.com/networking/tcp-proxy>). Que no toque el TLS se deduce, pero la página no lo dice.

### Computación confidencial
Un **enclave** es un entorno aislado cuya memoria no puede leer ni quien administra la máquina. La **atestación** es un documento firmado por el hardware que dice qué código exacto corre dentro: una **medición**, el hash de la imagen.

- **AWS Nitro Enclaves:**
  - Aísla con el hipervisor de Nitro, no con la CPU. El enclave no tiene disco persistente, ni acceso interactivo, ni red; solo un canal *vsock* con su instancia. Esta lista sale de una guía de terceros, no de AWS.
  - El *Nitro Security Module* firma un documento de atestación con las mediciones (`PCR0` es el hash de la imagen completa).
  - AWS KMS puede negarse a descifrar salvo para un enclave con cierto `PCR0` (`kms:RecipientAttestation:ImageSha384`): <https://docs.aws.amazon.com/enclaves/latest/user/kms.html>, <https://docs.aws.amazon.com/kms/latest/developerguide/conditions-nitro-enclaves.html>. Trail of Bits recomienda autorizar por `PCR0` y no usar comodines en el principal (<https://blog.trailofbits.com/2026/08/05/a-few-notes-on-aws-nitro-enclaves-kms-integration/>).
  - **Coste:** la función no se cobra aparte; se paga la instancia EC2 normal. Hay un tamaño mínimo, y las instancias *burstable* y *metal* quedan fuera (<https://aws.amazon.com/ec2/nitro/nitro-enclaves/faqs/>, <https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html>).
  - **Confianza que queda:** en AWS, que hace el hardware y el hipervisor. No en quien opera la cuenta de AWS.
- **TEE de CPU (AMD SEV-SNP, Intel TDX, Intel SGX):** la CPU cifra la memoria de la máquina virtual. Lo usan Google Confidential Space, que pone el `image_digest` del contenedor en el token de atestación y en producción no deja entrar por SSH (<https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims>), y los contenedores confidenciales de Azure (<https://learn.microsoft.com/en-us/azure/container-instances/confidential-containers-attestation-concepts>).
  - En 2025, **WireTap, Battering RAM y TEE.fail** rompieron SGX, TDX y SEV-SNP con un aparato de menos de 1000 USD entre la CPU y la memoria, con acceso físico (<https://tee.fail/>, <https://batteringram.eu/>). Intel y AMD dejan los ataques físicos fuera de su modelo.
  - Nitro no es un TEE de CPU y no estaba en el alcance de esos trabajos. Eso no prueba que sea inmune.
- **Apple Private Cloud Compute** (<https://security.apple.com/blog/private-cloud-compute/>): Apple publica la medición de todo el software de esos servidores en un registro de transparencia de solo anexar. El dispositivo **solo envuelve su petición para nodos cuya medición atestada esté en ese registro.** Un **registro de transparencia** es una lista pública que nadie puede reescribir sin que se note.
- **Signal:**
  - Desde 2017, Signal descubre contactos dentro de SGX, y el cliente comprueba la atestación antes de mandar nada (<https://signal.org/blog/private-contact-discovery/>).
  - Para recuperar llaves (SVR3), reparte el secreto entre enclaves de tres fabricantes (SGX en Azure, SEV-SNP en Google Cloud y Nitro en AWS), así que habría que romper los tres. Fuentes: el artículo de OSDI 2024 (<https://eprint.iacr.org/2024/887>) y <https://github.com/signalapp/SecureValueRecovery2>.

### Tokens hijos en cada proveedor
Un **token hijo** es una credencial corta y acotada que se crea con otra más amplia.

- **Railway:**
  - tokens de cuenta, de *workspace*, de proyecto (un entorno, cabecera `Project-Access-Token`) y de OAuth (<https://docs.railway.com/integrations/api>). No se documenta que venzan.
  - `projectTokenCreate` existe en el esquema GraphQL según código de terceros, no según la documentación. Pide un token de cuenta o de *workspace* y falla con el inicio de sesión de la CLI. No está confirmado que se puedan borrar por la API.
- **Northflank:** los tokens solo se crean en la interfaz o en el inicio de sesión de la CLI, con un rol y una duración (<https://northflank.com/docs/v1/application/secure/grant-api-access>). La API solo lista, rota y borra (<https://northflank.com/docs/v1/api/org/api-tokens/list-api-tokens>). **No hay forma de crear uno corto por la API.**
- **Maple:**
  - llaves `maple_ak_` con permisos acotados (`<familia>:read` o `<familia>:write`), creadas con `POST /v2/api_keys`. Vencen en 7 días como mínimo, o nunca.
  - Los tokens de OAuth duran 1 hora (<https://maple.dev/docs/reference/authentication/>).
  - El MCP acepta llaves de solo lectura desde el PR #2197 de MapleTechLabs/maple.

## Respuesta de Omar (2026-11-06)

Omar respondió en varias rondas. Las respuestas quedan aquí como decisiones; la última sobre el despliegue reemplaza a la anterior.

1. **Dónde corre T3 Code:** en su Mac. Es contexto, no diseño: Omar empieza conversaciones desde el teléfono y el Mac puede estar dormido, así que **el proxy no puede depender de que el Mac esté encendido** (§1).
2. **Qué herramientas necesitan credenciales:** la CLI de Northflank, la CLI de Railway y Maple por MCP, entre otras (§7, §12).
3. **Cifrado de punta a punta del sandbox al proxy,** porque los cuerpos de las peticiones pueden llevar secretos (por ejemplo, `northflank` creando el secreto de un servicio). **Ninguna llave de Klav puede quedarse en un sandbox;** lo único que vaya dentro debe estar muy controlado (§5, §6).
4. **Proxy alojado por Klav:** sí, dentro del plan alojado (20 USD al año), y también que cualquiera pueda alojarlo. Omar preguntó por qué el proxy tendría que sentarse entre el Mac y Boat: no tiene que hacerlo (§1).
5. **Sin proxy, las apps dicen claro qué se pierde** (§13).
6. **Configurar el proxy una vez, para toda la cuenta,** desde cualquier dispositivo. El proxy propio se empareja como un agente: 6 palabras y Touch ID o Face ID (§3).
7. **Confianza en el proveedor que aloja el proxy.** Omar preguntó si Railway vería las llaves de API en sus registros. La respuesta está en §11: los registros no las llevan, el borde de Railway solo ve texto cifrado si el canal va cifrado por dentro, y lo que sí puede leer quien opera la máquina es la memoria y las variables de entorno.
8. **Por qué el proxy tiene que ver el secreto, si la bóveda no lo ve.** Respondido en «Por qué el proxy tiene que ver el secreto».
9. **Coste del enclave:** Nitro Enclaves no cuesta aparte; se pagan instancias EC2 normales, con un tamaño mínimo y sin *burstable* ni *metal*. Es un coste fijo de infraestructura que se reparte entre todas las cuentas, no un coste por cuenta (§12).
10. **Despliegue (decisión final; reemplaza a la de empezar el proxy alojado sin enclave):**
    - **Klav no corre un proxy alojado que pueda ver texto en claro.** El proxy alojado solo sale como **proxy atestado en un enclave**, en una capa posterior. Su diseño, sus costes y su modelo de confianza quedan escritos ya en §12, para no perderlos.
    - **La primera entrega es el proxy propio:**
      - el programa;
      - las credenciales por sandbox (`klav sandbox start|stop|ls`);
      - el reenviador del sandbox con el canal cifrado de punta a punta;
      - las listas de permitidos;
      - las aprobaciones por el *push* y la app de iOS que ya existen;
      - la bitácora;
      - los *presets* de proveedores.
    - **Dónde se aloja el proxy propio:** el servidor de la persona (Railway, Fly, un VPS) o su Mac. El ajuste de la cuenta y el emparejamiento como agente se quedan como estaban.
    - **Queda resuelta la pregunta de si romper el cifrado de punta a punta para las credenciales concedidas al proxy alojado: no se rompe.** El proxy alojado sin enclave, con consentimiento explícito por credencial, pasa a «Alternativas descartadas».
11. **Las tres preguntas finales:** Omar aceptó el ADR el 2026-11-06 con las recomendaciones de «Preguntas para Omar», salvo la primera, que queda abierta:
    - **dónde aloja su proxy lo decide después.** Omar preguntó si Fly tiene enclaves, y pensó en Railway y en Northflank. Ninguno de los tres anuncia computación confidencial para sus clientes, así que el riesgo residual 53 es el mismo en todos. Lo que decide es T151: **el proxy no corre donde llegue alguno de los tokens que inyecta.**
      - **En Railway:** el proxy en un *workspace* aparte; solo se inyectan tokens de proyecto o de otro *workspace*, nunca uno de cuenta, porque un token de cuenta alcanza todos los *workspaces*.
      - **En Northflank:** igual, con tokens que no alcancen el proyecto del proxy.
      - **Lo más simple:** un VPS que no haga nada más, en un proveedor cuyos tokens no se inyectan.

      En cualquiera, la llave va en un archivo del volumen y nunca en una variable de la plataforma, porque las variables son lo que se filtró en los incidentes de octubre de 2026: Railway (desde el 21, según su aviso de seguridad, que pidió revocar todo lo guardado en variables) y Northflank (desde el 30, <https://status.northflank.com/cmvv0rn5a092f14rutwccodpp>, que pidió dar por descifradas todas las variables). El Mac queda como respaldo mientras esté despierto;
    - **grants por elemento desde la primera entrega** (capa 2);
    - **la variante del Mac (capa 11) va al final de la primera entrega,** después de los *presets*.

Omar dijo que le gusta el resto: el reenviador, la credencial del sandbox que no es una llave de Klav, el canal de punta a punta, los límites honestos y el manejo de los `.env`.

## Por qué el proxy tiene que ver el secreto
- **La bóveda solo guarda y sincroniza texto cifrado.** Se descifra en los dispositivos de la persona, que son también donde se usa el secreto: allí se rellena el formulario o se lanza el proceso.
- **Un proxy existe para usar el secreto.** La API de Northflank solo acepta el token real dentro de la petición TLS, así que lo que arma esa petición tiene que tener el valor en claro en ese momento. No hay forma de mandarle a Northflank un token cifrado que solo Northflank pueda abrir.
- **La pregunta real es dónde se usa el secreto:**

  | Dónde se usa | Cifrado de punta a punta frente a Klav | Lo que cuesta |
  |---|---|---|
  | En el dispositivo de la persona (su Mac) | Se mantiene | El dispositivo tiene que estar encendido y alcanzable |
  | En el sandbox | Se mantiene frente a Klav, pero el token queda en una máquina ajena y copiable | Es el problema de hoy |
  | En el servidor de la persona (proxy propio) | Se mantiene: Klav no ve nada | Hay que creer en quien opera ese servidor (§11) |
  | En los servidores de Klav | Se rompe para esas credenciales | Hay que creer en Klav y en su proveedor. **Descartado** (respuesta 10) |
  | En los servidores de Klav, dentro de un enclave verificable | Casi como la bóveda: la confianza pasa al fabricante del hardware y a código que cualquiera puede verificar | Infraestructura, compilación reproducible y verificación de la atestación en los clientes (§12) |

- **La salida por el lado del proveedor:** si el proveedor da tokens hijos cortos u OAuth con tokens de acceso cortos, nadie necesita tener el secreto de larga duración en otro sitio que los dispositivos de la persona (§17). Hoy Northflank no los da por la API.

## Decisión

### 1. Un solo programa, `klav-proxy`, en el sitio que elija la persona
- **`klav-proxy`** es un servicio que pone credenciales. Recibe la petición del sandbox, comprueba la política, pide el elemento al servidor de Klav, lo descifra en memoria, añade la cabecera del proveedor, abre él mismo el TLS hacia el proveedor y devuelve la respuesta.
- **Es el mismo programa en todos los sitios:**
  - **un servidor de la persona:** Railway, Fly o un VPS, con una imagen de Docker y una *template* de Railway;
  - **el Mac de la persona:** un *LaunchAgent* junto a `klavd`, no dentro de él;
  - **más adelante, el enclave de Klav** (§12).
- **No se sienta entre el Mac y Boat.** El sandbox habla con el proxy, y el proxy habla con el servidor de Klav y con el proveedor. El Mac solo hace falta si el proxy vive en el Mac, o si es el Mac quien crea el sandbox. En este último caso hace falta al **crearlo**, como ya pasa con T3 Code, y no durante la conversación.
- **Por qué no dentro de `klavd`:** `klavd` descifra con la bóveda abierta y la bloquea al dormir. Un proxy agente, con su propio grant, no necesita la bóveda abierta: funciona con el Mac bloqueado y con las aprobaciones por el teléfono. Así el código es el mismo en los tres sitios.

### 2. El proxy es un agente, con un grant por elemento
> Nota del 2026-11-09 (E10): la llave de un elemento compartida con HPKE pasa del tipo `0x22` al **`0x23`**, porque el ADR [0029](0029-anadir-dispositivo-con-qr.md), aceptado antes, ya tenía el `0x22`.

- **El proxy se empareja como cualquier agente** (ADR 0014 §1):
  - `klav-proxy init --email …` genera su identidad y se registra;
  - muestra las 6 palabras;
  - la persona las compara y aprueba con Touch ID o Face ID, en el Mac o en el iPhone.
  > Nota de implementación del 2026-11-10 (capas 3 y 4): el proxy no se aprueba con `klav agent approve`, que concede un grant de proyecto y el proxy nunca puede tener uno; lo aprueba su primer `klav proxy grant`, que pide las 6 palabras.
- **Su llave privada (`kag1_…`, tipo `0x07`)** vive solo donde corre el proxy: en un archivo 0600 dentro del volumen del servicio, o en el llavero del Mac. **Nunca en una variable de entorno de la plataforma** (§11).
  > Nota del 2026-11-18: la llave sigue en claro en reposo. El ADR [0044](0044-proxy-key-at-rest.md) (aceptado el 2026-11-18, sin construir) añade, por decisión de Omar del 2026-11-18 de hacerlo antes del lanzamiento, una alarma cuando la llave del proxy se usa desde una red nueva, una dirección de salida que la persona firma y el servidor exige (el perfil estricto, opcional; el de aviso es el de por defecto), y la memoria del proxy fuera del *swap* y de los volcados. Una copia de la llave robada sigue sirviendo desde el anfitrión del proxy.
- **La persona concede credenciales una por una.** El grant del proxy lleva **llaves de elemento**, no de proyecto.
  - Hoy un grant comparte la llave del proyecto (`0x21`, especificación §13.4), que abre todos sus elementos, también los que se añadan después.
  - Este ADR añade el tipo `0x23`, la llave de un elemento compartida con HPKE, con `info = tuple("klav/v1/share/item-key", account_id, vault_id, project_id, item_id, fingerprint_receptor)`, y un `GrantPayload` `v: 2` con una lista `items`.
  - El servidor solo entrega al proxy los elementos de esa lista.
  - Un proyecto dedicado con `Scope.items` (ADR 0032) se descartó: la llave del proyecto seguiría abriendo cualquier elemento que alguien añada ahí más tarde, y la única barrera sería el servidor (como el riesgo residual 44).
- **Un permiso nuevo, `proxy`:** usar el valor dentro de una petición HTTP que arma el proxy, sin devolverlo nunca.
  - No es `inject`, que pone el valor en un proceso (riesgo residual 31).
  - Un grant con `proxy` no lleva `reveal`, `inject` ni `fill`, y el servidor rechaza uno que los mezcle.
- **Destinos HTTP en la política:**
  - los hosts usan el campo `domains` que ya existe en `Scope`;
  - se añaden `methods` y `path_prefixes`.
  - `Scope` rechaza campos desconocidos (`deny_unknown_fields`), así que un cliente viejo falla cerrado ante una política nueva. Por eso el grant sube a `v: 2`.
- **Doble barrera, como hoy:** el proxy hace un `POST /v1/agent/access` firmado **por cada petición que inyecta** y declara método, host, ruta y sandbox, como hoy un agente declara el dominio (ADR 0014 §4). El servidor evalúa la política y registra el acceso, y el proxy vuelve a evaluarla con lo descifrado.
  - Así se reutilizan `ask`, la bitácora, `klav log verify`, la revocación y la pausa en la petición siguiente (ADR 0033 §7).
  - Cuesta una ida y vuelta al servidor por llamada. Si eso pesa, otro ADR puede agrupar; **nunca se guarda en caché la autorización.**
  - Para los servicios desplegados, el ADR [0038](0038-deployed-services.md) §7 (aceptado el 2026-11-09) cambia esto por un arrendamiento de 60 s por servicio, y lo dice. Los sandboxes siguen con el acceso por llamada.
- **Los perfiles viven en el grant.** Un **perfil** es una receta firmada por la cuenta: qué elemento, en qué cabecera y con qué formato, hacia qué hosts, métodos y rutas, qué pide aprobación y qué ritmo máximo. Por ejemplo, `northflank`, `railway` o `maple`. Los *presets* (§7) los rellenan.

### 3. El ajuste de la cuenta: qué proxy usa
- **Se configura una vez,** desde cualquier dispositivo o con `klav proxy use`. Se guarda en el elemento de sistema `preferences` (ADR 0032 §7): cifrado, sincronizado, en el proyecto de sistema que **ningún grant incluye**, así que ningún agente lo lee ni lo cambia.
  - Este ADR añade la clave `proxy: {mode: "none" | "own" | "klav", agent_id}`.
  - `klav` (el proxy alojado y atestado) solo existe cuando llegue la capa de §12.
  - Sin el elemento o sin la clave, vale `none`.
- **Quién lo lee:**
  - **las apps y la CLI de la persona,** al conceder una credencial, para envolverla para el proxy correcto, y para decir qué se pierde sin proxy (§13);
  - **el emisor** (el que crea sandboxes, §4), no directamente: cuando la persona aprueba el emisor o cambia el ajuste, su dispositivo firma un grant nuevo para el emisor con la dirección del proxy y la huella de su llave. Un servidor de sincronización malicioso no puede cambiar a qué proxy habla el emisor;
  - **el reenviador del sandbox,** que recibe la dirección, la huella y la credencial en el paquete de §4.
- **Cambiar de proxy es un interruptor de la cuenta.** Al cambiar, se revoca el grant del proxy anterior, se vuelven a envolver las credenciales para el nuevo con Touch ID o Face ID, y se cambia la llave de cada elemento que tenía el proxy anterior (§18).

### 4. Quién crea la credencial del sandbox: el emisor
> Enmienda del 2026-11-09 (E3.3, E6): el proxy registra `sandbox.issued` antes de devolver el paquete; `ls` y `stop` del emisor solo ven sus sandboxes; `--json` deja de llevar el paquete, que va al entorno del comando que sigue a `--` o a un archivo nuevo 0600 con `--package-file` (P4); la persona ve y revoca todos con `klav proxy sandboxes` y en «Sandboxes activos».

- **El emisor** es el programa que crea los sandboxes, aquí el lado servidor de T3 Code, dondequiera que corra. Es un agente de Klav más:
  - se registra con `klav agent register`, muestra 6 palabras, y la persona lo aprueba una vez;
  - su llave vive **donde ya vive la llave de la API de Boat**, en la misma zona de confianza: quien roba una, roba la otra;
  - **no lleva llaves de ningún elemento.** Su grant solo dice a qué proxy hablar, y el grant del proxy dice qué puede pedir ese emisor: perfiles, TTL máximo y cuántos sandboxes a la vez. La persona firma los dos.
- **`klav sandbox start --label chat-123 --profile northflank --profile maple [--ttl 8h] --json`**: el emisor manda al proxy una petición firmada con su llave, con la firma de agente que ya existe (especificación §13.3). El proxy comprueba que el emisor y los perfiles estén en su grant, crea el sandbox en su propio almacén (no en el servidor de Klav) y devuelve:
  - el **paquete del sandbox**, `ksb1_…`: `base64url(0x01 ‖ sandbox_id(16) ‖ secreto(32) ‖ u64_be(vence_ms) ‖ SHA-256(SPKI del proxy)(32) ‖ len ‖ url)`. Lleva versión desde el primer byte y quedará en la especificación (§13.10, junto a los formatos de agentes) con sus vectores. **No es una llave de Klav:** no descifra nada ni firma nada ante el servidor;
  - las líneas para el *setup script*.
- **Cómo llega al sandbox:** por el mismo camino que hoy `T3_NORTHFLANK_TOKEN`, en `KLAV_SANDBOX`. Boat ve ese valor y lo guarda, y por eso el secreto solo sirve una vez (§5).
- **Cada arranque es un paquete nuevo.** El *setup script* corre en cada arranque o reanudación, así que el emisor da un paquete nuevo cada vez y el anterior queda revocado.
- **`klav sandbox stop ID`** revoca enseguida. **`klav sandbox ls`** lista los sandboxes vivos, con su etiqueta, sus perfiles, su vencimiento y su última conexión.
- **Vencimientos:**
  - el TTL por defecto lo fija el grant (8 horas), con un máximo de 24 horas, como las tareas (ADR [0021](0021-solicitudes-de-tarea.md));
  - además, el sandbox se revoca después de 1 hora sin conexión, porque Boat no avisa al borrar.
- **Cuando el Mac está apagado:** si el emisor corre en el Mac, el Mac hace falta para **crear** la conversación, igual que hoy, y no después. Si T3 Code tiene un lado servidor que sigue vivo con el Mac dormido, el emisor vive ahí.

### 5. Qué vive en el sandbox: el reenviador
> Enmienda del 2026-11-09 (E3.3): el proxy registra `sandbox.claimed` antes de dar el secreto por gastado. Si el servidor lo rechaza, con el proxy en pausa, o no responde, el reclamo falla, el secreto sigue sin gastar y `klav-forward` lo guarda en memoria para reintentar: el paso 4 llega cuando el proxy acepta el reclamo. Con el proxy en pausa, el *push* de la señal de robo sale al reanudarse.

> Nota de implementación del 2026-11-11 (capa 6, `klav-forward up`):
> - **Solo el modo (a).** El reenviador pasa cada conexión local por una conexión propia del canal, byte a byte, sin leer HTTP: el proxy aplica el perfil y responde cada rechazo con su `Klav-Error`. El reenviador responde solo `klav_proxy_unreachable`. Por eso el proxy aplica en cada llamada del canal la misma comprobación de navegador que en su escucha local (`Origin`, `Sec-Fetch-Site` y un `Host` de *loopback*, con cualquier puerto): el reenviador no mira nada, y sin ella una página en un navegador del sandbox usaría los perfiles (revisión de #317). La aplica también a `GET /_klav/status` y `POST /_klav/release`, con `Host: klav-proxy` además, el del reenviador: sin ella, un formulario de otro sitio terminaría el sandbox y una página con *DNS rebinding* leería su estado. `claim` no la necesita: sin el secreto no tiene efecto. Así no necesita `hyper`, que Omar aprobó solo para `klav-proxy` y no para `klav-forward`. `up` deja una marca de reclamo sin secretos (`claimed/<sandbox_id>`, `v: 1`) antes del primer byte del reclamo, y un `up` posterior con el mismo paquete responde `klav_forward_already_claimed` sin conectarse, salvo que el reenviador de ese sandbox siga respondiendo, que dice que ya corre. Si ningún intento llegó a escribir la petición, la marca se borra y el paquete sigue sin usar ([api.md](../api.md) §8.11). La skill 0.3.1 suma a E1.2 una línea con ese código. `approval wait` y los modos (b) y (c) llegan después.
> - **El paso 1 sin entorno heredado.** `up` lee `KLAV_SANDBOX` y le pasa el paquete a un proceso hijo suyo por una tubería; el hijo arranca sin `KLAV_SANDBOX` y sin el paquete en sus argumentos. No puede borrar la variable del entorno de la *shell* que lo llamó, así que el *setup script* no debe pasársela a nada más.
> - **El paso 5 sin ser *root*.** Si no puede escribir `/etc/profile.d/klav-forward.sh`, deja las líneas en `~/.klav-forward/env.sh` y lo dice. Las líneas que da `klav sandbox start` usan `eval "$(klav-forward env)"`, que vale en los dos casos. Solo el modo (a): `KLAV_FORWARD_URL` y una `KLAV_FORWARD_<PERFIL>_URL` por perfil, sin valores de mentira (cada herramienta pone el suyo, que el proxy quita).
> - **Una llave del canal por sandbox:** cada `up` genera una y reclama el único paquete que tiene (#313).
> - **Cómo llega el binario a un sandbox de Boat** y si `/etc/profile.d` se puede escribir ahí: abierto, con Omar.
>
> Nota del 2026-11-17: el primer sandbox real de Boat corrió ese día. El binario llegó en una plantilla (un *snapshot* guardado de Boat), comprobado contra su SHA-256, y `/etc/profile.d` no se pudo escribir sin *root*, así que las líneas fueron a `~/.klav-forward/env.sh`. Cómo se arma y se rehace esa plantilla lo propone el ADR [0042](0042-sandboxes-for-daily-use.md) §7.

> **Decisión de Omar del 2026-11-16: una cuarta línea del *setup script* para el perfil `northflank`** (propuesta del 2026-11-12 en #349).
> - **Qué cambia.** Cuando el sandbox lleva el perfil `northflank`, `klav sandbox start` da una cuarta línea después de la del `eval`, en el texto y en `setup` de `--json`. La línea apunta la CLI de Northflank al reenviador con un token de mentira:
>   ```sh
>   northflank login -n klav -t klav-placeholder --override --host "$KLAV_FORWARD_NORTHFLANK_URL"
>   ```
>   `--host` usa la variable que acaba de poner `eval "$(klav-forward env)"`, no un puerto fijo: sigue al puerto real del reenviador. `--override` reemplaza un contexto `klav` que quedó de un arranque anterior. Con otros perfiles nada cambia, y `next` dice además lo que pide el perfil (abajo).
> - **Qué revierte.** Para esta herramienta, la nota de implementación del 2026-11-11 de arriba, que dice «sin valores de mentira (cada herramienta pone el suyo, que el proxy quita)». `klav-forward env` sigue sin valores de mentira: la línea va en lo que da `klav sandbox start`, no en el entorno. Antes de esa nota, el paso 5 de esta sección y el *setup script* de §14 ya llevaban un `northflank login` con `klav-placeholder`.
> - **Por qué.** La nota del 2026-11-11 suponía que cada herramienta pone su valor y que quien escribe el *setup script* añade lo que haga falta. Pero la herramienta que integra Klav en un ejecutor de sandboxes corre solo las líneas que Klav da. Sin esta línea, ese sandbox tiene un reenviador que funciona y una CLI de Northflank que no apunta a él.
> - **Por qué el valor de mentira no es una credencial.** El proxy quita cualquier `Authorization` que mande una herramienta y pone el real (§7, «Siempre, en los tres modos»). `klav-placeholder` nunca sale del sandbox como credencial: solo llega al reenviador en `127.0.0.1`, y el proxy lo descarta.
> - **Lo que no está comprobado.**
>   - La CLI de Northflank se leyó (`@northflank/cli` 0.15.0) y no se corrió.
>   - Su `login` comprueba el contexto con `GET <host>/v1/login`, con un plazo de 3 s y 3 intentos. El perfil `northflank` que firma la persona tiene que dejar pasar ese `GET` sin aprobación: si pide una, el `login` falla antes de que la persona responda.
>   - Los comandos de la CLI que van por WebSocket probablemente fallan a través del proxy.
> - **Alternativas que se miraron.**
>   - Las variables de entorno de la CLI para el token y la URL base, en las líneas de `klav-forward env`. No se eligieron: solo valen en las *shells* que leen esas líneas, y volverían a poner un valor de mentira en `klav-forward env`. El `login` guarda un contexto de la CLI con nombre (`-n klav`).
>   - Un puerto fijo (`http://127.0.0.1:8790/northflank`, el que usa por defecto `klav-forward up --daemon`). Omar eligió la variable.
>   - Que la herramienta que integra escriba su propia línea. Lo descarta la regla de Omar de que esa herramienta corra solo las líneas que da Klav.
> - **Relación con los *presets*.** Es la primera línea por perfil, y se adelanta a la capa de *presets* del roadmap («Presets `northflank`, `railway` y `maple`, probados en un sandbox de Boat»). Esa capa es donde se probará en un sandbox de Boat.

- **`klav-forward`** es un binario pequeño que no contiene código de la bóveda: no sabe descifrar elementos ni firmar como agente. **El reenviador** escucha en `127.0.0.1` y pasa las peticiones al proxy por el canal de §6.
- **`klav-forward up`:**
  1. lee `KLAV_SANDBOX` y la borra del entorno;
  2. genera en memoria la **llave del canal**, un par Ed25519 que no sale del proceso;
  3. abre el canal fijado (§6) presentando esa llave y **reclama** el sandbox con el secreto. El proxy liga el sandbox a la llave del canal y da el secreto por gastado; desde ahí solo vale esa llave;
  4. borra el secreto de su memoria;
  5. escribe la configuración que no es secreta: `/etc/profile.d/klav-forward.sh` con `HTTPS_PROXY`, `NODE_USE_ENV_PROXY=1`, `NODE_EXTRA_CA_CERTS` y `SSL_CERT_FILE` en el modo (b), las URL base del modo (a), la entrada MCP del modo (c) (en lo construido la escriben las líneas de `klav sandbox start`, no `up`: nota del 2026-11-19 en §7), y valores de mentira para las herramientas que exigen un token para arrancar (por ejemplo, `northflank login -t klav-placeholder --host …`).
- **Un segundo reclamo con el mismo secreto es la señal de robo:** el proxy revoca el sandbox y manda un *push* a la persona. Si Boat, o quien copió el entorno, reclama primero, el reenviador legítimo falla y la persona se entera igual.
- **Lo que hay en el sandbox, completo:**

  | Dónde | Qué | Para qué sirve si se roba |
  |---|---|---|
  | Memoria del reenviador | La llave del canal | Usar el proxy como el sandbox: los perfiles, las listas, las aprobaciones, hasta `stop`, el TTL o 1 hora sin conexión |
  | Memoria del reenviador, solo en el modo (b) | La llave de la CA del sandbox | Firmar certificados que solo se aceptan en ese sandbox y solo para los hosts permitidos (restricción de nombres de X.509) |
  | Disco | El certificado de la CA (público), la configuración de las herramientas y los valores de mentira | Nada |
  | Entorno, solo hasta el reclamo | `KLAV_SANDBOX` | Nada después del reclamo; antes, ganar la carrera y quedar detectado |

- **Quien copia todo el disco y toda la memoria del sandbox** se lleva lo mismo que el agente ya tenía: usar el proxy con esos perfiles mientras el sandbox viva. **No se lleva ningún token de proveedor ni ninguna llave de Klav.** Al revocar el sandbox, lo copiado deja de servir.

  > Nota del 2026-11-18: Omar decidió ese día, en la Q8 del ADR [0045](0045-keyless-services.md) (aceptado, sin construir), que los sandboxes tengan la detección de copias de los servicios desplegados, en el mismo trabajo que los servicios. No es trabajo del lanzamiento: se diseña y se construye con el *ratchet* del ADR 0038 (§5), reusando lo que sirva, y hasta entonces esta línea sigue valiendo. Cuando se construya, deja de aceptar una copia que siga funcionando junto al original. Lo que se reusa, lo que no y lo que vuelve a Omar antes de construirlo está en el ADR 0045 §10.1.

### 6. El canal: TLS 1.3 con llaves fijadas, de punta a punta
- **El reenviador abre TLS 1.3 directo con el proceso del proxy:**
  - el certificado del proxy se acepta solo si su llave pública coincide con la huella del paquete; es lo que se llama **fijar** la llave (*pinning*);
  - el reenviador se autentica con la llave del canal, como certificado de cliente;
  - se usa `rustls` con `aws-lc-rs`, ya aprobados para transporte (ADR [0011](0011-cliente-tls-y-jerarquia-local.md)), con llaves públicas en bruto (RFC 7250) o certificados autofirmados. **No hace falta ninguna dependencia criptográfica nueva para el canal.**
- **Se descartó Noise:** pediría la dependencia `snow` y su ADR, y no da nada que TLS con llaves fijadas no dé aquí.
- **`hyper` y `hyper-util` como dependencias directas de `klav-proxy`** (nota del 2026-11-11, **aprobadas por Omar el 2026-11-11**): `hyper` 1.12 con `server` y `http1`, y `hyper-util` 0.1.21 con `tokio` y `service`. Sirven HTTP/1.1 sobre el canal fijado conexión por conexión, con lo que `axum::serve` no deja controlar: un plazo para la cabecera de cada petición, cerrar una conexión sola con gracia (al terminar su sandbox o al desalojarla) y saber de qué llave es cada conexión. Ya estaban en el árbol, a través de `axum` y `reqwest`: `Cargo.lock` no gana ningún paquete. Son transporte, nunca criptografía, y nunca entran en `klav-core`.
- **Un chorro de *handshakes* desechables puede retrasar un reclamo** (revisión de #304/#306, 2026-11-11). Con 32 conexiones sin sandbox o más llegando sin parar entre el *handshake* de un reenviador y la cabecera de su reclamo, la conexión del reenviador es la más vieja y se desaloja; como todavía no mandó ni un byte, `hyper` la cierra al momento, sin gracia, y el reclamo falla mientras dure el chorro (el reenviador reintenta). Una vez llegada la cabecera, el reclamo corre aparte y termina aunque se desaloje la conexión. Su vuelta al servidor (`sandbox.claimed`) tiene el plazo del cliente HTTP de Klav: 10 s para conectar y 60 s en total. Ese es el tiempo más largo en que la llave sigue sin ligarse; mientras tanto, un reintento con la misma llave recibe `429` y, cuando el servidor responde, el `200` del reclamo ya hecho. `docs/api.md` §8.10 lo cuenta igual.
- **Lo que hay en medio solo ve texto cifrado:** la red de Boat, el borde del proveedor del proxy, Tailscale o un relevo.
  - En Railway, el canal va por el *TCP Proxy*, que reenvía bytes.
  - Donde solo haya entrada HTTPS, el TLS interno viaja dentro de un WebSocket. El borde descifra la capa de fuera y sigue viendo cifrada la de dentro.
- **Para llegar al proxy en el Mac:**
  - **Primera capa: Tailscale.** El emisor crea por la API, para cada sandbox, una llave de un solo uso, efímera, preaprobada y con la etiqueta `tag:klav-sandbox`, que solo puede llegar al puerto del proxy en `tag:klav-proxy`. Va en el mismo paquete de arranque, y `tailscaled` corre con `--state=mem:`, así que el nodo desaparece al apagarse. El canal TLS va igual por dentro. Lo que de verdad corta el acceso es revocar el sandbox, no la llave de Tailscale.
    > Nota del 2026-11-17: el paquete `ksb1_` (especificación §13.10) no tiene campo para la llave de Tailscale, y el cliente OAuth de Tailscale cambia su secreto por un token en el cuerpo de la petición, que `klav-proxy` no sabe rellenar. El primer sandbox real (2026-11-17) usó una llave hecha a mano. Omar decidió ese día (ADR [0042](0042-sandboxes-for-daily-use.md) §2 y §4) que, por ahora, un *script* del anfitrión del proxy crea la llave con un cliente OAuth de Tailscale acotado a `auth_keys` y a `tag:klav-sandbox`, que guarda el usuario del sistema del emisor; que la llave va en una variable aparte, `KLAV_TAILNET_KEY`, nunca en el paquete; y que el proxy haga el intercambio y cree la llave queda para después, sin fecha.
  - **Más adelante, solo si alguien lo necesita: un relevo ciego en `klav.dev`.** Une la conexión del reenviador con una conexión saliente del Mac por el ID del sandbox y solo pasa bytes cifrados, como el relevo del ADR [0029](0029-anadir-dispositivo-con-qr.md). Mantiene el cifrado de punta a punta y evita pedir Tailscale.
  - **Descartados para el canal:**
    - Cloudflare Tunnel, porque descifra en su borde y pide `cloudflared` y un inicio de sesión en el sandbox;
    - ngrok, que funcionaría con *endpoints* TLS, pero añade otra cuenta de terceros por persona.

### 7. Cómo llega el tráfico, y los *presets*
- **Modo (a), URL base:** sin interceptar TLS. La herramienta habla HTTP en claro con `127.0.0.1` y el reenviador lo manda por el canal. **Es el modo por defecto** donde la herramienta lo permite.
- **Modo (b), `HTTPS_PROXY` y una CA del sandbox:**
  - la CA la genera el reenviador en memoria al arrancar, con restricción de nombres a los hosts de los perfiles, y muere con él;
  - el certificado público va a `NODE_EXTRA_CA_CERTS` y a un `SSL_CERT_FILE`, que es la lista del sistema más esta CA;
  - solo lo usan las herramientas que no dejan otra opción, como la CLI de Railway;
  - generar certificados X.509 pide `rcgen` (con `aws-lc-rs`, solo para transporte), y este ADR lo propone para esa capa.
- **Modo (c), puerta MCP:** el cliente MCP apunta a `http://127.0.0.1:PUERTO/mcp/maple`, y el proxy reenvía a `https://api.maple.dev/mcp` con `Authorization: Bearer maple_ak_…`. El *streaming* (SSE) pasa tal cual. (Lo construido usa `/maple/mcp` y límites propios para los *streams*: nota del 2026-11-19, abajo.)
- **Siempre, en los tres modos:**
  - el proxy **quita** cualquier `Authorization`, `Cookie` o cabecera del proveedor que mande el sandbox (los valores de mentira) y pone la real;
  - **no sigue redirecciones;**
  - resuelve el DNS él mismo y **rechaza al conectar** las direcciones privadas, de *loopback* y de metadatos de la nube;
  - verifica el TLS del proveedor con las raíces de `webpki`.
- **Presets:**

  | Preset | Modo | Credencial | Cabecera | Permitido por defecto | Pide aprobación por defecto |
  |---|---|---|---|---|---|
  | `northflank` | (a); (b) si `--host` no funciona | API token | `Authorization: Bearer` | `api.northflank.com`, todos los métodos | `DELETE`, y cambios de roles o de tokens |
  | `railway` | (b) | Token de proyecto (preferido) o de cuenta | `Project-Access-Token` o `Authorization: Bearer` | `backboard.railway.com/graphql/v2`, `POST` | Las *mutations* que borran (el proxy lee el nombre de la operación GraphQL) |
  | `maple` | (c) | `maple_ak_` | `Authorization: Bearer` | `api.maple.dev/mcp` | Ninguna; se recomienda una llave de solo lectura |

  Los *presets* son puntos de partida: la persona ve y edita el perfil antes de firmarlo.

  > Nota del 2026-11-17 (capa 10, el *preset* `northflank`, con la decisión de Omar del 2026-11-16): la fila de `northflank` no se puede construir tal como está escrita. Una credencial lleva como mucho 4 métodos entre los que pasan y los que piden aprobación (`MAX_GRANT_METHODS`, para que el diálogo de Touch ID o Face ID los muestre todos sin recortar), así que «todos los métodos» no cabe. Además, una sola lista de prefijos de ruta sirve a la vez a los métodos que pasan y a los que preguntan, así que «pedir aprobación solo en estas rutas» (los cambios de roles o de tokens) no se puede decir sin opciones por ruta, que no existen. Omar decidió el 2026-11-16:
  > - `GET`, `POST` y `PATCH` pasan sin preguntar y `DELETE` pide aprobación. No hay `PUT`: una llamada con `PUT` se rechaza, y el *preset* lo dice donde la persona lo lee.
  > - Los cambios de roles y de tokens quedan fuera del *preset*, que lo dice con palabras: nada en él los protege por ruta. No se añaden opciones de aprobación por ruta ni se adivinan rutas de la API de Northflank.
  > - Lo demás, como la fila: el token de API, `Authorization: Bearer`, `api.northflank.com` (todas las rutas, `/`) y el ritmo por defecto.
  >
  > `klav proxy grant ITEM --preset northflank` lo construye en la CLI ([cli.md](../cli.md)): rellena las mismas opciones que la persona escribiría, cada opción que añade reemplaza esa parte, y el perfil sale con los mismos bytes que esas opciones explícitas. `railway` y `maple` se rechazan hasta que existan los modos (b) y (c).

> **Nota del 2026-11-19 (capa 9, la puerta MCP, con las decisiones de Omar del 2026-11-19).** Omar aprobó ese día construir el modo (c) y el *preset* `maple` en cinco PRs en pila. Para no confundirlos con las capas de este ADR, se llaman aquí **pasos M1 a M5**.
>
> **Lo que encontró la lectura del código.** Un perfil de Maple cabe en los campos que ya firma un grant del proxy (host, cabecera, prefijo, campo, métodos, prefijos de ruta y ritmo). No hace falta ningún campo firmado ni formato binario nuevo, ni cambiar la especificación o sus vectores, ni el servidor, ni añadir una dependencia. Lo que hoy rompe una sesión MCP está en el proxy:
> - un plazo total de 120 s para cada llamada, respuesta incluida (`DEFAULT_REQUEST_TIMEOUT`);
> - el corte tras 60 s sin un trozo nuevo (`BODY_IDLE`);
> - la redacción en *stream*, que retiene el final de cada trozo (los últimos bytes, menos que el patrón más largo), así que un evento llega al cliente solo cuando llega el trozo siguiente.
>
> **Las decisiones de Omar (2026-11-19):**
> 1. **El host.** Su organización de Maple está en el host de EE. UU., `api.maple.dev`, y el *preset* lo usa. `--upstream https://api.eu.maple.dev` cambia al europeo. Es un solo *preset*, no dos.
> 2. **La llave.** El proxy guarda una llave de API de Maple restringida, con permisos de solo lectura y que vence a los 90 días. Toda llamada MCP es el mismo `POST` a `/mcp`, así que el proxy no puede dejar pasar ni preguntar por herramienta: el límite son los permisos de la llave.
> 3. **Aprobar por herramienta** (preguntar antes de una herramienta que escribe) no se diseña ahora. Pediría un campo nuevo en la regla firmada, su propio ADR y una ronda de actualizaciones de los dispositivos. Queda como trabajo futuro.
> 4. **La URL local es `/maple/mcp`:** el cliente MCP apunta a `http://127.0.0.1:<puerto>/maple/mcp`. El enrutado del modo (a) la sirve sin cambios (perfil `maple`, ruta `/mcp` en el proveedor), sin nombre reservado y sin ruta del proveedor en el perfil firmado, que el formato no admite.
> 5. **Los límites de un *stream*.** Una respuesta en *streaming* (`text/event-stream`) puede seguir abierta 15 minutos como mucho, se corta tras 2 minutos sin datos y nunca dura más que su sandbox. Las respuestas que no son un *stream* siguen con los 120 s en total. En un *stream*, los 120 s cubren solo las cabeceras.
> 6. **La entrada del cliente.** El servidor MCP se configura en el sandbox con líneas de *setup* que `klav sandbox start` da para el perfil `maple`. Esas líneas corren la CLI del propio cliente (`claude mcp add`, `codex mcp add`) cuando está instalada. `klav-forward` no edita archivos de configuración de los clientes, así que no gana ninguna dependencia.
> 7. **El ritmo** queda como está: 60 llamadas por minuto por sandbox, compartidas entre perfiles, y el valor por defecto del perfil firmado, 60. Se mide en la prueba a mano (M5).
> 8. **Los métodos.** El *preset* `maple` deja pasar `POST`, `GET` y `DELETE`, y ninguno pide aprobación. Los clientes MCP de hoy solo mandan `POST`; los de revisiones anteriores del protocolo abren un *stream* con `GET` y cierran la sesión con `DELETE`.
> 9. **El orden.** La primera capa del ADR [0044](0044-proxy-key-at-rest.md) (la llave del proxy en reposo, que deja la memoria del proxy fuera de la *swap* y de los volcados de memoria) entra antes del paso M3, porque los *streams* tienen el valor inyectado más tiempo en memoria.
>
> **Dónde se aparta lo construido del texto de este ADR:**
> - **La URL.** El modo (c) de arriba dice `http://127.0.0.1:PUERTO/mcp/maple`. Lo que se construye es `/maple/mcp` (decisión 4). Para el proxy, la puerta MCP no es un modo de enrutado nuevo: es un perfil del modo (a) más los límites de *stream* del paso M3.
> - **Quién escribe la entrada del cliente, y con qué.** El paso 5 de §5 dice que `klav-forward up` escribe «la entrada MCP del modo (c)». No la escribe: la escriben las líneas de *setup* que da `klav sandbox start` para el perfil `maple`, con la CLI del cliente (decisión 6), como la cuarta línea del perfil `northflank` (decisión de Omar del 2026-11-16, en §5). Las líneas exactas salen de la documentación pública de cada CLI en el paso M4; esta nota no las fija.
> - **El valor de mentira.** La entrada del cliente lleva `Authorization: Bearer klav-placeholder`, que el proxy quita y reemplaza por el real (arriba, «Siempre, en los tres modos»). Sirve para que el cliente no tome un `401` o un `403` del proxy por una petición de iniciar sesión. Como el `klav-placeholder` de `northflank`, nunca sale del sandbox como credencial. La nota del 2026-11-11 en §5 («sin valores de mentira») sigue valiendo para `klav-forward env`: este valor va en la entrada del cliente, no en el entorno.
> - **Los límites de un *stream*** (§8, «un tiempo máximo por petición»), según la decisión 5:
>   - el proxy reconoce un *stream* por el `Content-Type: text/event-stream` de la respuesta;
>   - el plazo de 120 s cubre solo sus cabeceras;
>   - puede estar abierto 15 minutos como mucho y se corta tras 2 minutos sin un trozo nuevo;
>   - se corta cuando termina su sandbox, por cualquier motivo: la revocación de la persona, el TTL, la señal de robo, la liberación por el reenviador, la inactividad o el emisor quitado. De la revocación, el proxy se entera en el siguiente acceso (`403 sandbox_revoked`) o en el barrido de las revocaciones, que corre cada 30 s (E3.3, punto 2), así que un *stream* sin llamadas nuevas dura como mucho unos 30 s más que la revocación. Los fines que decide el propio proxy (TTL, inactividad, emisor quitado) salen de su barrido, que también corre cada 30 s;
>   - se corta cuando la persona pausa los agentes (elección del plan que Omar confirmó, abajo): una pausa ya corta toda llamada nueva (`klav_agents_paused`);
>   - mientras está abierto ocupa uno de los 4 huecos del sandbox (`SANDBOX_IN_FLIGHT`) y uno de los 16 del proxy (`MAX_IN_FLIGHT`). Un sandbox con 4 *streams* abiertos no puede hacer más llamadas hasta que uno termine; se mide en M5.
>
>   Un corte termina la respuesta con un error, nunca con un final limpio, como hoy.
> - **La fila del *preset*** (tabla de arriba), según las decisiones 1, 2, 7 y 8:
>   - host `api.maple.dev`, que `--upstream https://api.eu.maple.dev` cambia;
>   - `Authorization: Bearer` con la llave restringida de solo lectura que vence a los 90 días, y `POST`, `GET` y `DELETE` sin aprobación;
>   - el prefijo de ruta es `/mcp`, no `/` (elección del plan que Omar confirmó, abajo);
>   - el ritmo por defecto.
>
>   «Modo (c)» en la fila quiere decir esta puerta MCP sobre el enrutado del modo (a).
>
> **El cambio en la redacción (paso M2).** El `StreamRedactor` de `klav-sdk` gana una forma opcional de emitir: en cada trozo emite todo hasta el último CR o LF que vio, incluido, en vez de retener siempre el final.
> - **Por qué no pierde nada de lo que hoy se reemplaza.** Ningún patrón del redactor contiene CR ni LF si el valor no los contiene:
>   - JSON los escribe `\n` y `\r`, y la codificación URL `%0A` y `%0D`;
>   - base64 y hex no tienen esos bytes.
>
>   Así que una coincidencia nunca cruza un fin de línea, y lo que está antes del último se puede revisar y emitir de una vez. El resultado es el mismo que redactar todo el cuerpo de golpe.
> - **Un valor que contiene un salto de línea.** El redactor vuelve a la regla de hoy. En el proxy no pasa: un valor con CR o LF no cabe en una cabecera, y el proxy lo rechaza antes de crear el redactor (`profiles.rs`).
> - **Por qué no es un oráculo.** Cuándo salen los bytes depende solo de dónde están los fines de línea del proveedor, nunca del valor ni de si algo coincidió.
>   - No retiene «solo un final que empieza como el valor», que filtraría el valor byte a byte por el tiempo.
>   - Tampoco retiene más una coincidencia que cruza el corte, que la regla de hoy sí retiene un poco más.
> - **El tope de 1 MiB** de lo retenido sigue igual: una línea más larga que el tope se corta como error, nunca como un final limpio.
> - **Quién lo usa.** El proxy solo lo pedirá para las respuestas `text/event-stream`, en M3 (elección del plan que Omar confirmó, abajo). Las demás respuestas siguen con la regla de hoy, y `klav sandbox start` no lo pide para la salida de un comando.
>
> **Una corrección pendiente en otro ADR.** El ADR [0044](0044-proxy-key-at-rest.md) dice dos veces que la copia del valor que tiene el redactor vive como mucho 120 s: en «The problem, checked in the code» («The redactor») y en §3.3. Con los *streams* vive hasta el máximo de un *stream*, 15 minutos. Esas dos frases hay que corregirlas cuando entre el paso M3.
>
> **Elecciones del plan, las más estrictas, que fallan cerradas. Omar las confirmó todas el 2026-11-19:**
> - el prefijo de ruta del *preset* es `/mcp`, no `/`: una llamada a otra ruta de Maple, como la de descubrir OAuth, se rechaza;
> - la emisión por fin de línea solo para `text/event-stream`;
> - en M3, un *stream* abierto se corta también cuando la persona pausa los agentes, no solo cuando termina su sandbox;
> - en M3, el proxy quita `WWW-Authenticate` de **toda** respuesta a un sandbox, también en los perfiles que ya existen, como ya quita `Set-Cookie`. Hoy la deja pasar (T148), y con ella un cliente MCP podría empezar un inicio de sesión OAuth con Maple, que le daría una credencial suya que sirve sin el proxy.
> - una línea de un *stream* más larga que el tope de 1 MiB corta la respuesta como error, sin volver a la regla de hoy ni subir el tope; cuánto pesan los eventos reales de Maple se mide en M5.
>
> **Lo que no está comprobado:**
> - cómo responde Maple a través del proxy: si contesta un `POST` con un *stream* o con JSON, cuánto deja abierto un *stream*, y cómo usa la cabecera `Mcp-Session-Id`;
> - cómo reacciona cada cliente a un `401` o un `403`, y que el valor de mentira lo evite;
> - la sintaxis exacta de `claude mcp add` y `codex mcp add`;
> - si el ritmo de 60 llamadas por minuto alcanza.
>
> Todo eso se comprueba en M4 y M5.
>
> **Los cinco pasos y su orden:**
> 1. **M1, documentos:** esta nota y las filas del modelo de amenazas (T149 cambiada, T226–T228 y el riesgo residual 93).
> 2. **M2, `klav-sdk`:** la emisión opcional por fin de línea del `StreamRedactor`. Nadie la pide todavía, así que nada cambia en el producto.
> 3. **M3, `klav-proxy`:** reconocer un *stream*, el plazo solo para las cabeceras, los límites de un *stream* y el corte al revocar y al vencer. Entra después de la primera capa del ADR 0044 (decisión 9).
> 4. **M4, `klav-cli`:** `--preset maple` y las líneas de *setup* del perfil `maple`.
> 5. **M5:** una prueba a mano en un sandbox real, que mide el ritmo y los huecos y marca la casilla del modo (c) en el roadmap.

> **Nota del 2026-11-25 (pasos M3 y M4 construidos).** M2 ya estaba en el código desde la publicación del repositorio (v0.9.0): `StreamRedactor::by_lines` y sus pruebas en `klav-sdk`. Este trabajo construyó M3 y M4; M5 sigue abierto. Lo que se aparta de la nota del 2026-11-19 o la precisa:
> - **Qué se corta.** Toda llamada en curso, no solo un *stream*, se corta cuando termina su sandbox o la persona pausa los agentes: la espera de las cabeceras del proveedor responde `401 klav_sandbox_revoked` o `423 klav_agents_paused`, y un cuerpo a medias termina en un error. Una pausa corta también las llamadas en curso de los programas de la máquina del proxy. Cada llamada se registra antes de pedir el elemento al servidor, así que no se pierde un fin que llegue después.
> - **Cuándo se entera el proxy.** Al momento, de los fines que decide él (`stop`, robo, `released`); en su barrido, cada 30 s, del TTL, la inactividad, el emisor quitado y las revocaciones de la persona; al refrescar su grant, cada 30 s, de una pausa de todos los agentes; y cuando el servidor rechaza otra llamada de un sandbox, de su revocación (`sandbox_revoked`) o de la pausa de su emisor (`agents_paused`, que corta los *streams* de todos los sandboxes de ese emisor). Una pausa de un solo emisor sin llamadas nuevas no se nota hasta que su sandbox llame. Además, ninguna respuesta pasa del `expires_at` de su sandbox.
> - **Un cliente que se va** suelta su respuesta y sus huecos en cuanto el proxy nota que se fue: por el canal, que acepta el semicierre, cuando falla la siguiente escritura (el siguiente trozo del proveedor), o al límite de inactividad si el proveedor calla.
> - **Las líneas de *setup*** (decisión 6), con la sintaxis comprobada con Claude Code 2.1.331 y Codex 0.166.0, corridas dos veces con `sh -e`:
>   ```sh
>   if command -v claude >/dev/null 2>&1; then claude mcp remove --scope user maple >/dev/null 2>&1 || true; claude mcp add --transport http --scope user maple "$KLAV_FORWARD_MAPLE_URL/mcp" --header "Authorization: Bearer klav-placeholder"; fi
>   if command -v codex >/dev/null 2>&1; then codex mcp add maple --url "$KLAV_FORWARD_MAPLE_URL/mcp"; fi
>   ```
>   `claude mcp add` rechaza una entrada que ya existe, así que la línea quita antes la llamada `maple`, también una que la persona hubiera puesto a mano en el sandbox.
> - **Codex va sin el valor de mentira.** La nota del 2026-11-19 dice que la entrada del cliente lleva `Authorization: Bearer klav-placeholder`. `codex mcp add` solo toma un *bearer* de una variable de entorno (`--bearer-token-env-var`), no una cabecera fija, y escribir su `config.toml` a mano iría contra la decisión 6. La entrada de Codex queda sin él. **Lo decide Omar:** dejarlo así, si M5 muestra que Codex no toma un `401` o un `403` del proxy por un inicio de sesión, o pedir otra forma.

### 8. Política: qué puede hacer cada sandbox
- **Listas de permitidos por perfil:** hosts, métodos y prefijos de ruta, firmados en el grant. El emisor elige perfiles y puede acortar el TTL, no ampliar nada.
- **`ask` para lo peligroso:** `DELETE` y lo que marque el perfil (§9).
- **Ritmo:** un máximo por sandbox (60 peticiones por minuto por defecto) y otro por perfil. También un tamaño máximo de cuerpo y un tiempo máximo por petición, con los cuerpos en *streaming*. (Para una respuesta `text/event-stream`, los límites y la emisión por fin de línea de la nota del 2026-11-19 en §7.)
- **Redacción de respuestas:** el proxy busca el valor inyectado en las cabeceras y el cuerpo de la respuesta, con las codificaciones que ya cubre el `Redactor` de `klav-sdk` (base64, hex, URL, JSON y trozos de 12 caracteres o más), y lo reemplaza. Desde la capa 6 reemplaza solo el valor entero, nunca un trozo, y los trozos solo los cuenta (respuesta de Omar sobre T149, E9). No descomprime: pide `identity` y bloquea una respuesta con cualquier otro `Content-Encoding` (nota de implementación del 2026-11-11: esta frase decía que descomprimía `gzip`, `br` y `deflate`, y el código nunca lo hizo).
- **La política no se puede ampliar desde el sandbox,** ni desde el emisor. Solo una firma nueva de la cuenta la cambia.

### 9. Aprobaciones y bitácora
> Enmienda del 2026-11-09 (E3.3): dos acciones más en la tabla cerrada, `sandbox.claimed` (del proxy) y `sandbox.revoke_requested` (firmada por la cuenta), y los motivos `person`, `person_local`, `released` (el reenviador suelta el suyo, que antes era `stop`) e `issuer_removed` en `sandbox.revoked`.

- **Una llamada en `ask` crea una aprobación en el servidor** (ADR 0014 §5, ADR [0015](0015-aprobaciones-reutilizables-y-espera.md)), que llega por *push* al iPhone y al Mac, sin que haga falta el Mac.
  - La tarjeta dice el sandbox (su etiqueta, según el emisor), el método, el host y la ruta, tal como los ve el proxy, no como los cuenta el agente.
  - La persona aprueba con Face ID o Touch ID, una vez o por un rato (arrendamiento, hasta 24 horas).
- **El proxy retiene la petición hasta 2 minutos** mientras espera. Si no hay respuesta, devuelve `klav_approval_pending` con el `approval_id` (§10). El reintento de la herramienta es el mismo destino, así que gasta la aprobación cuando llegue (ADR 0015 §2), sin que la herramienta tenga que mandar nada nuevo.
- **Bitácora:** cada petición inyectada es un acceso firmado por el proxy, con permiso `proxy` y los datos de la llamada (sandbox, método, host y ruta, nunca cuerpos ni cabeceras). Se añaden a la tabla cerrada de `klav log verify` (ADR [0030](0030-ronda-de-seguridad-2026-11.md) §4) dos acciones con petición firmada del proxy: `sandbox.issued` (con el emisor) y `sandbox.revoked` (con el motivo: `stop`, TTL, inactividad o robo). La etiqueta y la ruta se muestran como texto plano «según el proxy», como pide T136 del modelo de amenazas.

### 10. Cuando el proxy no responde
El reenviador nunca deja una herramienta colgada sin explicación. Responde HTTP con la cabecera `Klav-Error` y un JSON:

```json
{"error":"klav_proxy_unreachable",
 "message":"Klav's credential proxy did not answer (its host may be down, or the Mac that runs it is asleep).",
 "next":"Tell the person this exact message and stop. Do not retry in a loop and do not look for the token elsewhere."}
```

| `error` | HTTP | Cuándo |
|---|---|---|
| `klav_proxy_unreachable` | 503 | El reenviador no llega al proxy: su servidor está caído o el Mac duerme |
| `klav_server_unreachable` | 503 | El proxy no llega al servidor de Klav |
| `klav_sandbox_expired` / `klav_sandbox_revoked` | 401 | TTL, `stop`, inactividad o señal de robo |
| `klav_agents_paused` | 423 | La persona pausó los agentes (ADR [0033](0033-agentes-desde-la-app-de-mac.md) §7) |
| `klav_not_allowed` | 403 | Fuera de la lista del perfil |
| `klav_approval_pending` | 409 | Con `approval_id` y `expires_at` |
| `klav_approval_denied` | 403 | La persona dijo que no |
| `klav_rate_limited` | 429 | Con `retry_after` |
| `klav_upstream_blocked` | 502 | Dirección privada, redirección o cuerpo que no se puede revisar |
| `klav_proxy_backlog` | 503 | El proxy tiene demasiados fines de sandbox esperando al servidor y no empieza ninguno más (solo `klav sandbox start`) |

> Nota de implementación del 2026-11-10 (capa 6, revisión de #304): `klav_proxy_backlog` se añadió a esta tabla. Antes, un proxy con la cola de fines llena respondía `klav_server_unreachable`, que no era cierto: el servidor podía responder. Una CLI anterior lo trata como cualquier rechazo del proxy: muestra su `message` y su `next` y sale con 1.

`klav-forward status` devuelve los mismos estados con los códigos de salida del ADR 0015. Lo que dice la skill sobre sandboxes lo define la enmienda del 2026-11-09 (E1). La skill pide al agente decir a la persona el mensaje tal cual, no reintentar en bucle y no buscar el token por otro lado. Con `klav_approval_pending`, debe decir qué pidió y esperar con `klav-forward approval wait ID`, en segundo plano.

### 11. El proxy propio en un servidor ajeno: a quién hay que creerle
Esto responde a la pregunta de Omar sobre Railway (respuesta 7). Vale para cualquier proveedor que aloje el proxy propio.

- **Los registros de la aplicación nunca llevan tokens:** el proxy no imprime valores (`SecretBox`, sin `Debug`) ni cuerpos.
- **El borde del proveedor:** el de Railway descifra el TLS de sus dominios públicos. Vería la credencial del sandbox y los cuerpos si el canal no fuera cifrado por dentro. Con el canal de §6, solo ve texto cifrado.
- **La salida hacia Northflank** la abre el propio proxy con TLS, así que el proveedor también ve ahí solo texto cifrado.
- **Pero quien opera la máquina puede leer la memoria, el disco y las variables de entorno del contenedor.** Si la llave privada del proxy está en una variable de entorno o en su memoria, el proveedor podría, en principio, usarla. Sin enclave, el proxy propio en Railway significa creer en Railway como operador.
- **El servidor de sincronización en Railway no cambia:** solo guarda texto cifrado y nunca tiene llaves.
- **Reglas para alojarlo:**
  - un servicio aparte, nunca dentro del servidor de sincronización;
  - la llave la genera `klav-proxy init` en un archivo 0600 de un volumen, nunca en una variable de la plataforma, que se ve en el panel, en la CLI del proveedor y en cada despliegue;
  - **ningún token que el proxy inyecte puede llegar al servicio donde corre el proxy.** Si el proxy corre en Railway y pone un token de cuenta de Railway, un agente podría usar el proxy para leer las variables o el volumen del propio proxy, sacar su llave y con ella pedir y descifrar todas las credenciales concedidas;
  - en Railway, el proxy va en otro *workspace* y los tokens que pone son de proyecto (`Project-Access-Token`), que no llegan a él;
  - mejor aún, en otro proveedor distinto de los que inyecta: Fly o un VPS para quien inyecta tokens de Railway;
  - `klav proxy grant` avisa cuando el host del perfil es el del proveedor donde corre el proxy.
  > Nota del 2026-11-18: el ADR [0044](0044-proxy-key-at-rest.md) (aceptado, sin construir) dice qué cambia para quien opera la máquina: la alarma y la salida firmada no lo detienen (usa la llave desde la misma dirección), y el proxy desactiva los volcados de memoria y bloquea su memoria contra el *swap* cuando el anfitrión lo permite.
- **Lo que se gana y lo que se paga:**
  - **Railway** es lo que Omar ya usa y lo más simple, pero deja un tercero de confianza más.
  - **Un VPS propio** reduce los operadores, pero hay que mantenerlo.
  - **El Mac** no añade operadores, pero tiene que estar despierto.

### 12. El proxy alojado y atestado (capa posterior, la única versión alojada)
Respuesta 10: el proxy alojado solo existe así. Se escribe ahora para no perderlo.

- **Qué es:** `klav-proxy`, compilado de forma reproducible, corre dentro de un AWS Nitro Enclave operado por Klav.
  - El enclave genera su llave dentro y la pone en su documento de atestación.
  - Habla con el exterior por *vsock* a través de su instancia. El TLS del canal (§6) y el de salida hacia el proveedor terminan **dentro** del enclave, así que la instancia solo pasa bytes cifrados.
- **El modelo de confianza:**
  - los operadores de Klav no pueden leer la memoria del enclave;
  - **antes de envolver una credencial para el enclave**, los dispositivos de la persona (iOS, Mac y CLI) comprueban su atestación: que la firme el *Nitro Security Module*, que la medición (`PCR0`) sea la de una versión publicada del código abierto, compilada de forma reproducible y anotada en un registro de transparencia (como hace Apple), y que la llave del enclave sea la de ese documento;
  - así la confianza pasa del personal de Klav a AWS como fabricante del hardware y a un código que cualquiera puede compilar y comparar. Es lo más cerca de la bóveda que puede estar un proxy.
- **Por qué Nitro y no un TEE de CPU:** no cuesta aparte, se integra con KMS por medición y no está en el alcance de los ataques físicos de 2025 contra SGX, TDX y SEV-SNP. Lo que queda es creer en AWS. Repartir el secreto entre varios fabricantes, como el SVR3 de Signal, es el techo posible, y queda fuera de alcance.
- **Persistencia y actualizaciones:**
  - la llave privada del enclave se guarda sellada con KMS, con una condición de `PCR0`, así que un reinicio con la misma imagen la recupera;
  - **una versión nueva cambia la medición:** el enclave viejo solo entrega la llave a uno nuevo tras comprobar su atestación y que su medición esté en el registro. Si eso falla, los dispositivos vuelven a envolver las credenciales con Face ID o Touch ID.
- **La identidad del proxy alojado** no la da el servidor. Los clientes fijan en el binario la llave de firma del registro de transparencia, como fijan `api.klav.dev` (ADR [0028](0028-servidor-por-defecto-klav-dev.md)). Un servidor malicioso no puede colar otra llave.
- **Costes:**
  - **infraestructura:** Railway no tiene enclaves; hacen falta instancias EC2 normales, de un tamaño mínimo, ni *burstable* ni *metal*. La función no se cobra aparte. Es un **coste fijo compartido** entre todas las cuentas del plan, no un coste por cuenta;
  - **complejidad:**
    - compilación reproducible de la imagen;
    - verificar la atestación (CBOR, COSE, la cadena de certificados de AWS y ECDSA P-384) en iOS, Mac y CLI, con dependencias que pedirán su propio ADR;
    - la entrega de la llave entre versiones;
    - el registro de transparencia;
  - **canales laterales:** el código del enclave tiene que ser de tiempo constante con los secretos, y queda la confianza en AWS.
- **Abuso y coste en el plan alojado:** el proxy pasa cuerpos en las dos direcciones (`railway up` sube el código), así que hay cuotas por cuenta de peticiones, de bytes y de sandboxes a la vez, más un tamaño máximo de cuerpo y un ritmo por sandbox. Las listas firmadas impiden usarlo como proxy abierto: solo llega a los hosts que la persona firmó. Este ADR no promete precios.
- **Cuando esté en los tres clientes,** podrá ser el modo por defecto de la cuenta en el plan alojado.

  > Nota del 2026-11-18: el ADR [0045](0045-keyless-services.md) (aceptado el 2026-11-18, sin construir) recoge la decisión de Omar de ese día: el proxy alojado queda fuera del lanzamiento y sigue en la lista de espera, y si algún día se construye, el enclave guarda solo llaves de firma por cliente (la federación de identidad de cargas), nunca llaves de proveedor. Desde que se escribió esta sección, el boletín de AWS 2026-157-AWS (2026-10-30) corrigió en la v0.4.6 del SDK de Nitro Enclaves para C dos fallos, uno de los cuales dejaba a una aplicación de la instancia madre ejecutar código dentro del enclave (en el ejemplo `kmstool-enclave` o en código derivado de él). Sin confirmar: un artículo de 2026 sobre un canal lateral de caché desde la instancia madre con root, y si existe un verificador del atestado en Swift.

### 13. Lo que se pierde sin proxy, y dónde lo dicen las apps
> Enmienda del 2026-11-09 (E1.3, E4): qué le dice el agente a la persona sin proxy lo fija el error `klav_no_proxy` de `klav sandbox start`, y la fila «Proxy de credenciales» del Mac pasa a ser la cabecera de Desarrollo › Sandboxes.

**Sin proxy (`proxy.mode = none`), la persona pierde:**
1. `klav sandbox` entero: credenciales por sandbox que no son llaves de Klav, que mueren al parar el sandbox y que se pueden revocar al instante;
2. usar Northflank, Railway, Maple y los demás *presets* desde un sandbox sin que el token entre en él;
3. las aprobaciones por llamada y la bitácora de cada llamada, con método, host y ruta;
4. la puerta MCP para servidores MCP remotos sin poner el *bearer* en el cliente;
5. la señal de robo cuando alguien reclama dos veces un sandbox.

Lo que sigue funcionando: los agentes locales (`klav run`, `inject`, MCP), con su riesgo residual 31. Dentro de un sandbox, eso supone una llave de Klav en él, y Klav no lo recomienda.

**Con el proxy en el Mac**, todo lo anterior funciona solo mientras el Mac está despierto y alcanzable.

**Dónde se dice:**
- **Mac:** en la sección «Desarrollo» (ADR 0033 E1), una fila «Proxy de credenciales» con el estado («Sin proxy», «Tu proxy: proxy.ejemplo.com», «En este Mac»). Sin proxy, la fila dice en una frase lo que se pierde y ofrece «Configurar».
- **iOS:** en Ajustes, una fila «Proxy de credenciales» con lo mismo.
- **En cada credencial:** «Usar desde sandboxes», desactivado con la misma frase.
- **CLI:** `klav proxy status`, y el error de `klav sandbox start`, que dice qué falta y cómo configurarlo.

### 14. Comandos
> Enmienda del 2026-11-09 (E6): la persona gana `klav proxy sandboxes [revoke]` y `klav proxy issuer add|remove`; `klav sandbox start` gana `-- comando` y `--package-file`.

**De la persona (cualquier dispositivo):**

| Comando | Qué hace |
|---|---|
| `klav proxy use own AGENTE` / `klav proxy use none` | Cambia el ajuste de la cuenta. El proxy en el Mac también es `own` |
| `klav proxy status` | Muestra el proxy, sus 6 palabras, qué credenciales y perfiles tiene, y qué se pierde sin él |
| `klav proxy grant ITEM --preset northflank` | Concede una credencial con un perfil; muestra el perfil y pide Touch ID o Face ID |
| `klav proxy revoke ITEM` | Quita la credencial del grant y cambia la llave del elemento (§18) |
| `klav agent approve` | Empareja el proxy y el emisor, como hoy |

> Nota de implementación del 2026-11-10 (capas 3 y 4): `klav agent approve` ya no empareja el proxy, porque concede un grant de proyecto y el proxy nunca puede tener uno; el proxy lo aprueba su primer `klav proxy grant`, con sus 6 palabras (§2).

**Del emisor:** `klav sandbox start|stop|ls` (§4).

**Del proxy:** `klav-proxy init` y `klav-proxy serve`.

**Del sandbox:** `klav-forward up|status|env|approval wait`.

> Nota de implementación del 2026-11-12 (capa 6): `klav-forward down [--json]` suelta el sandbox en el proxy (`POST /_klav/release`, motivo `released`, una vez y con 10 s como mucho) y para el reenviador, que libera su puerto. Se lo pide por un *socket* Unix en el directorio de estado (`down.sock`, 0600, solo del mismo uid, con una confirmación tras `ready` para que una petición abandonada nunca se atienda), nunca con una señal al PID de `state.json`, que tras un reinicio puede ser de otro proceso: parar el proceso pide el mismo usuario que una señal, y no hacen falta `unsafe`, una dependencia ni el programa `kill`. Con un puerto de *loopback*, cualquier usuario del sandbox podría pararlo. Soltar el sandbox no es lo que esto protege: cualquier programa local ya puede pedirlo por el puerto en claro del reenviador (`POST /_klav/release`, [api.md](../api.md) §8.10), y `down` no cambia eso. Si el proxy no responde o ya terminó el sandbox, `down` para el reenviador igual y dice qué pasó; sin reenviador, sale con `0` sin crear nada, y dos `down` a la vez salen los dos con `0`. Nunca dice que el puerto quedó libre si sigue ocupado. Una señal (`SIGTERM`, Ctrl-C) sigue parándolo sin soltar el sandbox, y así se queda: lo decidió Omar el 2026-11-13 («Las preguntas abiertas de la capa 5a»). Tras cualquier parada el sandbox ya no se puede usar, porque la llave del canal solo vivía en la memoria del reenviador; sin `down`, conserva su plaza de `--max-live` hasta `klav sandbox stop`, su TTL o 1 hora sin llamadas. Un reenviador nuevo necesita un paquete nuevo de `klav sandbox start`. `klav-forward env --json` da en una línea lo mismo que las líneas `export`. Las líneas de `klav sandbox start` no cambian (cambian el 2026-11-15: ver la nota siguiente). Detalle en [api.md](../api.md) §8.11.

> Nota de implementación del 2026-11-15: las líneas de `klav sandbox start` empiezan ahora por `klav-forward down --if-other-package`, antes de `klav-forward up --daemon` y `eval "$(klav-forward env)"`. Un sandbox que se reanuda con su memoria (el proveedor lo suspende y lo despierta) conserva vivo el reenviador de su paquete. Si recibe un paquete nuevo, ese reenviador tiene ocupado el puerto, y sin la primera línea el `up` del paquete nuevo se niega con `klav_forward_port_in_use` (antes de reclamar, así que el paquete nuevo sigue sirviendo). Con `--if-other-package`, `down` lee de `KLAV_SANDBOX` solo el ID del sandbox, igual que `up`, sin imprimir, registrar ni guardar nada más del paquete, tampoco en un error. Decide en este orden, sin contactar, soltar, escribir ni borrar nada antes: el paquete, el `state.json`, si nombra el sandbox del paquete, la marca de reclamo de ese sandbox y, al final, lo de `down`:
>
> - **Si el `state.json` del directorio de estado nombra ese sandbox**, no toca nada (ni el *socket*, ni la liberación, ni un archivo), esté su reenviador vivo, ocupado o muerto, y sale con `0`. `up` hace entonces lo que hacía sin esa línea: dice que ya corre; pasa el rechazo del proxy para ese sandbox con su código (`5` revocado o no permitido, `6` vencido, `7` con los agentes en pausa, `1` lo demás); o, si su reenviador murió, se niega con `klav_forward_already_claimed`. Así, correr las líneas otra vez con el mismo paquete (un proveedor que repite el *setup script* al reanudar, una persona que lo vuelve a lanzar) no rompe un sandbox que funciona. Un `down` sin la opción lo soltaría en el proxy y pararía su reenviador, y `up` ya no podría reclamar el paquete gastado.
> - **Si `KLAV_SANDBOX` no está o no es un paquete, o si el `state.json` no se puede leer**, no para nada y sale con `0`: no sabe qué reenviador es el de este paquete, y `up` dice lo que encuentre. Una línea que existe para no parar el reenviador equivocado no adivina.
> - **Si la marca de reclamo de este paquete está en el directorio de estado** (cualquiera: una que no se lee o de otra versión cuenta, como en `up`), no para nada y sale con `0`. El paquete ya se gastó aquí, así que `up` lo rechazará con `klav_forward_already_claimed` igual que sin esta línea. Es el caso de un proveedor que guardó el entorno al crear el sandbox y repite el paquete viejo al reanudarlo, sobre el reenviador de un paquete más nuevo: sin esta comprobación, `down` soltaría el sandbox más nuevo y pararía su reenviador antes de que `up` se negara. Cubre también el reenviador de este paquete vivo sin `state.json` (`up` solo registra que no pudo guardarlo).
> - **Si no hay `state.json` o nombra otro sandbox, y este paquete no se reclamó aquí**, hace lo mismo que `down`: suelta ese sandbox en el proxy y para su reenviador, o sale con `0` sin hacer nada donde no corre ninguno. Solo sale con `1` (`klav_forward_cannot_stop`) cuando no puede parar el reenviador de otro paquete que tiene el puerto. Con `set -e` eso para el *script*, y `up` tampoco arrancaría con el puerto ocupado.
>
> Las líneas necesitan un `klav-forward` de esta versión de Klav o posterior, el primero con `down --if-other-package`. Con uno anterior, la primera línea sale con `2` (`unexpected argument '--if-other-package' found`, o `unrecognized subcommand 'down'` si es anterior a `down`) y `set -e` para el *script* antes de `up`, sin reclamar nada: con un `klav-forward` actual en la imagen, las mismas líneas con el mismo paquete funcionan. `klav sandbox start` no mira la versión de `klav-forward`, y `klav-forward --version` aún no distingue unas de otras (todas dicen `0.0.0`). La skill pasa a la versión 0.3.2 para decirlo; el extracto de la skill de la enmienda del 2026-11-09, más abajo, queda como estaba. Las pruebas de `crates/klav-forward/tests/up.rs` corren las líneas leídas del código de `klav-cli`, con `sh -e`: `the_setup_lines_take_over_from_a_forwarder_still_running` (otro paquete), `the_setup_lines_run_again_with_the_same_package_leave_its_forwarder_alone`, `the_setup_lines_leave_this_packages_busy_forwarder_alone`, `the_setup_lines_leave_a_gone_forwarder_of_this_package_to_up`, `the_setup_lines_never_stop_a_newer_package_for_an_old_one_replayed`, `the_setup_lines_leave_this_packages_forwarder_without_state_json_alone`, `down_if_other_package_takes_an_unreadable_marker_as_claimed` y `down_if_other_package_stops_nothing_when_it_cannot_tell`. Detalle en [cli.md](../cli.md), `klav sandbox start`, y en [api.md](../api.md) §8.11.

**El *setup script* de T3 Code queda así** (con `klav-forward down --if-other-package` delante desde el 2026-11-15, ver la nota de arriba; con `eval "$(klav-forward env)"`, que vale con y sin `/etc/profile.d`, desde la nota del 2026-11-11 de §5; y con la línea de `northflank login` solo para un sandbox con el perfil `northflank`, por la decisión del 2026-11-16 de §5):

```sh
klav-forward down --if-other-package   # para el reenviador de otro paquete, si sigue vivo; el de este lo deja
klav-forward up --daemon            # lee KLAV_SANDBOX y la borra
eval "$(klav-forward env)"          # las URL locales, sin secretos
northflank login -n klav -t klav-placeholder --override --host "$KLAV_FORWARD_NORTHFLANK_URL"   # solo con el perfil northflank
```

### 15. `klav agent run --exec` para servidores MCP por stdio
Esto se mantiene del encargo original y es independiente del proxy.

- **`klav agent run --exec [--timeout 0] -- comando`** hereda la entrada, la salida y el error estándar, no captura nada y por defecto no tiene tiempo máximo. Sirve para lanzar un servidor MCP local que necesita un token.
- **Lo que se pierde es la redacción de la salida:** lo que el proceso escriba va directo al cliente MCP y al LLM.
- Pide el permiso `inject`, como `run`; la bitácora lo registra como `run` con `exec: true`, y el CLI avisa una vez por stderr.
- **No es para sandboxes,** porque necesita una llave de Klav. Allí se usa la puerta MCP (§7, modo c).

### 16. Archivos `.env` en los *worktrees*
- **Lo que hace Klav:**
  - `klav env import .env --env NOMBRE` ya ofrece borrar el archivo (ADR 0032);
  - un comando nuevo, **`klav env scan [DIR]`**, busca `.env` y `.env.*` (salvo `.env.example`), dice si git los ignora o los sigue, y ofrece importarlos;
  - la skill pide a los agentes no escribir nunca un `.env` y usar `klav run` en local o el reenviador en un sandbox. La parte de los sandboxes la define la enmienda del 2026-11-09 (E1); la regla general sobre `.env` llega con la capa 13.
- **Lo que tiene que hacer quien aloja T3 Code:**
  - no copiar `.env` a los *worktrees*;
  - no pasar tokens reales a los *setup scripts*, solo `KLAV_SANDBOX`;
  - llamar a `klav sandbox stop` y borrar el *worktree* y el sandbox al borrar la conversación.
- Klav no puede impedir que otro programa escriba un `.env`; solo encontrarlo y ofrecer sacarlo.

### 17. Tokens hijos del proveedor (capa opcional)
Donde el proveedor lo permita, **el dispositivo de la persona** crea un token hijo corto al empezar el sandbox y lo envuelve para el proxy. El token largo nunca sale de sus dispositivos.

| Proveedor | Hoy |
|---|---|
| Maple | Factible: `POST /v2/api_keys` con permisos acotados, pero vence en 7 días como mínimo, así que el proxy la borra en `stop` |
| Railway | Sin documentar (`projectTokenCreate`) y sin vencimiento conocido |
| Northflank | No se puede: la API no crea tokens |

Pide un dispositivo encendido al empezar el sandbox, que es justo lo que Omar quiere evitar. Por eso es opcional y va después.

### 18. Límites honestos
- **Mientras el sandbox vive, el agente puede hacer todo lo que permiten sus perfiles a través del proxy.** El proxy no hace bueno al agente: acota qué puede tocar, deja registro de cada llamada y pide permiso para lo marcado.
- **Lo que gana el proxy:**
  - el token no puede salir del sandbox, porque nunca entró;
  - el acceso termina en el momento en que se revoca el sandbox;
  - cada sandbox es distinguible en la bitácora.
- **Boat ve lo que el agente manda y recibe dentro del sandbox:** cuerpos de peticiones, salida de comandos y archivos. Nada esconde los datos de la máquina donde corre el agente. Lo que el diseño deja fuera son los tokens de los proveedores y cualquier llave de Klav.
- **El agente puede sacar datos por los hosts permitidos:** por ejemplo, guardar algo en un secreto de Northflank. La lista limita adónde, no qué.
- **Revocar el grant para al proxy honesto, pero no «des-comparte» una llave.** Un proxy, o su operador, que guardó la llave de un elemento la sigue teniendo, y las llaves de elemento no cambian al rotar el proyecto (especificación §5.2). Por eso `klav proxy revoke` y el cambio de proxy **cambian la llave del elemento** (llave nueva, secciones selladas de nuevo), y la app recomienda **rotar el token en el proveedor**.
- **Las herramientas que se saltan el proxy** (sockets directos, otro programa) no obtienen el token: fallan. Boat no controla la salida, así que tampoco se puede obligar al tráfico a pasar por el proxy.

## Alternativas descartadas
- **(A) Delegar la identidad: un agente de Klav por sandbox,** con un grant corto. Deja una llave de Klav dentro del sandbox, que Omar prohíbe, y el valor acaba en el entorno del proceso (riesgo residual 31). Además pedía un protocolo nuevo de delegación en el servidor y formatos firmados nuevos. Podría volver solo para máquinas de confianza de la persona.
- **Proxy alojado por Klav sin enclave, con consentimiento explícito por credencial.** Klav y su proveedor podrían leer las credenciales concedidas mientras durara el grant, y después si guardaran la llave del elemento. Separar servicios y llaves, la bitácora firmada y la revocación limitan el daño, pero no lo evitan. Omar decidió que Klav no corra nada que vea texto en claro (respuesta 10).
- **El proxy dentro del servidor de sincronización:** juntaría un servicio que solo ve texto cifrado con uno que ve valores, y romper uno sería romper los dos.
- **`klavd` como proxy, con la bóveda abierta:** dependería del Mac despierto y desbloqueado. Se queda la versión agente en el Mac (§1).
- **El proxy de credenciales de Boat:** pone los tokens en manos de Boat, está documentado para credenciales de IA y se cobra por día.
- **Un token por sandbox en una variable,** o el token compartido de hoy: sigue siendo el token real dentro del sandbox.
- **El secreto sellado dentro del sandbox, como `tokenizer`:** una copia del sandbox serviría mientras el proxy lo aceptara, y revocarlo pide estado en el proxy de todas formas.
- **Un proxy sin autenticación de cliente, como Secretless:** cualquier proceso que llegue al puerto lo usaría, también desde fuera del sandbox si el puerto se expone.
- **Noise para el canal:** una dependencia nueva sin ganancia frente a TLS 1.3 con llaves fijadas (§6).
- **Cloudflare Tunnel como canal:** descifra en el borde y pide software y sesión en el sandbox.
- **Un proyecto dedicado con `Scope.items` en vez de grants por elemento:** la llave del proyecto abriría lo que se añada después, y la única barrera sería el servidor (§2).

## Seguridad
Las amenazas nuevas están en el modelo de amenazas, §5.17 (T147–T161), y los riesgos residuales 51 a 56, marcados «aceptado, pendiente de implementar». La enmienda del 2026-11-09 añade T168–T173 y los riesgos 61–64, también «aceptado, pendiente de implementar» (E7). La nota del 2026-11-19 sobre la puerta MCP (§7) cambia T149 y añade T226–T228 y el riesgo 93, igual de pendientes.

## Plan por capas
Cada capa es un PR de la pila, con sus pruebas, su casilla en el roadmap y, donde toque, la especificación y sus vectores.

**Primera entrega: el proxy propio**
1. **Este ADR** y el modelo de amenazas.
2. **Grants por elemento:**
   - el tipo `0x23` y el `GrantPayload` `v: 2` con `items`;
   - el permiso `proxy`;
   - `methods` y `path_prefixes` en `Scope`;
   - el servidor solo entrega los elementos concedidos;
   - especificación §8 y §13.4, con vectores;
   - cambiar la llave de un elemento al revocarlo.
3. **`klav-proxy`:**
   - emparejamiento como agente, llave en un archivo 0600 o en el llavero;
   - acceso por llamada al servidor;
   - inyección, listas, defensa SSRF, redacción y ritmo;
   - el modo (a);
   - imagen de Docker y *template* de Railway, en un servicio aparte.
4. **El ajuste de la cuenta y la concesión:**
   - la clave `proxy` en `preferences`;
   - `klav proxy use|status|grant|revoke`;
   - «Usar desde sandboxes» en Mac e iOS;
   - lo que se pierde sin proxy (§13).
5. **El emisor y `klav sandbox start|stop|ls`:**
   - el paquete `ksb1_` (especificación §13.10, con vectores);
   - el grant del emisor;
   - TTL e inactividad;
   - `sandbox.issued` y `sandbox.revoked` en la tabla cerrada de `klav log verify`.
6. **`klav-forward` y el canal:** TLS 1.3 con llaves fijadas, el reclamo ligado a la llave del canal, la señal de robo, los errores de §10 y la skill (su texto, en la enmienda del 2026-11-09, E1). La enmienda suma piezas a las capas 4, 5, 6 y 11, y añade las capas 5a, 6a y 6b (E8).
7. **Aprobaciones:** `ask` por llamada, por el *push* y la app de iOS que ya existen, con la tarjeta del sandbox y la espera de 2 minutos.
8. **El modo (b):** la CA del sandbox con restricción de nombres y la dependencia `rcgen`.
9. **El modo (c):** la puerta MCP (en cinco pasos, M1 a M5: nota del 2026-11-19 en §7).
10. **Presets:** `northflank`, `railway` y `maple`, probados en un sandbox de Boat.
11. **El proxy en el Mac:** el *LaunchAgent* y Tailscale con llaves efímeras por sandbox.

**Independientes**

12. **`klav agent run --exec`** (§15).
13. **`klav env scan`** y las reglas de la skill sobre `.env` (§16).

**Después**

14. **Relevo ciego en `klav.dev`** para el proxy en el Mac, solo si alguien lo necesita sin Tailscale.
15. **Proxy atestado:**
    - imagen reproducible de Nitro;
    - registro de transparencia;
    - verificación de la atestación en iOS, Mac y CLI, con su ADR de dependencias;
    - entrega de la llave entre versiones.
16. **Proxy alojado en el plan:** depende de la capa 15. Incluye la infraestructura en EC2, las cuotas por cuenta, el modo `klav` del ajuste y, cuando esté en los tres clientes, el modo por defecto del plan.
17. **Tokens hijos** donde el proveedor los permita (§17).

## Consecuencias
- **Formatos nuevos** (cada uno con versión, especificación y vectores en su capa):
  - el blob `0x23`;
  - el `GrantPayload` `v: 2`;
  - el paquete `ksb1_`;
  - la clave `proxy` de `preferences`;
  - el permiso `proxy`;
  - `methods` y `path_prefixes` en `Scope`.
  - La sección §13.9 de la especificación sigue reservada para la pausa (ADR 0033).
- **El servidor cambia:** verifica grants `v: 2`, entrega elementos sueltos y guarda los datos de la llamada en los accesos y las aprobaciones. Esto corrige una idea de una ronda anterior («sin protocolo nuevo en el servidor»), que solo valía para un proxy dentro de `klavd`. **La API del proxy vive en el proxy, no en el servidor de sincronización**, y el servidor nunca ve las credenciales de los sandboxes.
- **Binarios nuevos:** `klav-proxy` y `klav-forward`. Ninguno implementa primitivas: el descifrado pasa por `klav-core`, y el TLS por `rustls` con `aws-lc-rs`.
- **Dependencias:** `rcgen` para el modo (b), solo transporte, propuesta aquí. Lo que pida la verificación de la atestación tendrá su propio ADR.
- **Lo que no aparece:** ningún servicio de Klav ve credenciales en claro; el servidor sigue siendo de conocimiento cero; ningún sandbox lleva tokens de proveedor ni llaves de Klav.
- **El encargo de «un solo comando»** queda en `klav sandbox start`, que el emisor corre; la persona configura una vez su proxy y concede cada credencial.

## Preguntas para Omar
Respondidas el 2026-11-06: Omar aceptó las tres recomendaciones («Respuesta de Omar», punto 11). Las de la enmienda del 2026-11-09 las respondió el 2026-11-09, con la recomendación de cada una (E9).

1. **¿Dónde alojas tu proxy al principio?**
   - **Recomendación:** en Fly o en un VPS pequeño, fuera de Railway, porque vas a inyectar tokens de Railway y ningún token inyectado debe llegar al servicio del propio proxy (§11).
   - Si prefieres Railway, en otro *workspace* y solo con tokens de proyecto.
   - El Mac, como respaldo, mientras esté despierto.
2. **¿Grants por elemento desde la primera entrega (capa 2), o empezar con un proyecto dedicado y `Scope.items`?**
   - **Recomendación:** por elemento desde el principio. Es una capa de formato con vectores, pero el proxy corre en una máquina que opera otro, y esa es la barrera criptográfica que importa ahí. El proxy atestado la necesitará igual.
3. **¿La variante del Mac (capa 11) va al final de la primera entrega, como está en el plan, o la sacamos a «Después»?**
   - **Recomendación:** al final de la primera entrega, después de los *presets*. Tu caso es el teléfono con el Mac dormido, así que el proxy en un servidor va primero. El Mac sigue siendo una opción para quien no quiera ningún servidor, con Tailscale, y el relevo ciego solo si alguien lo pide.

## Enmienda del 2026-11-09
Omar no corre código en sandboxes hoy porque las API keys y las credenciales se quedan dentro, y no sabe cómo preparar Klav para hacerlo. El 2026-11-09 pidió dos cosas:

1. **Que la skill de Klav lo enseñe:** un agente que prepara Klav tiene que saber empezar un sandbox efímero con Klav sin dejar nada dentro (E1).
2. **«Sandboxes activos» en las apps de Mac e iOS:** qué sandboxes viven, quién los creó y cuándo vencen, con «Revocar» y «Revocar todos» (E2–E6).

**Ya decidido por Omar:** revocar no pide nada, ni Face ID ni Touch ID, como pausar los agentes (ADR [0033](0033-agentes-desde-la-app-de-mac.md) P2). Revocar solo quita acceso; nunca lo da (E2.3).

**Lo demás lo respondió Omar el mismo día,** con la opción recomendada de cada pregunta (E9), y con eso aceptó la enmienda. La revisión de la enmienda dejó dos preguntas más, Q-C y Q-D, que Omar respondió también con la opción recomendada, y una aclaración de P6 (E9). E10 mueve la llave de un elemento compartida del §2 al tipo `0x23`. Las secciones de arriba siguen valiendo salvo donde esta enmienda dice otra cosa, y sus notas remiten aquí.

### E1. La parte de los sandboxes en la skill
Esta sección es el único sitio que define lo que dice la skill sobre sandboxes. §10, §13, §16 y la capa 6 remiten aquí.

#### E1.1 Dónde vive y qué va en cada sitio
- **La skill es `skill/SKILL.md`.** `crates/klav-cli/src/skill.rs` la incrusta en el binario (`include_str!`), con su versión en `metadata.klav-skill-version` y el SHA-256 de cada versión publicada en `PUBLISHED`; una prueba falla si el archivo cambia sin versión nueva (ADR 0033 §6). Hoy mide 103 líneas.
- **Sigue la regla del ADR 0033 E3.2:** la skill guarda las reglas que no dependen de una opción, y el binario que corre dice los detalles.

  | Dónde | Qué |
  |---|---|
  | La skill | Cuándo hace falta un sandbox, qué nunca entra en él, cómo se empieza y se para, qué hacer sin proxy, que dentro del sandbox no se conecta con Klav, y cómo leer un error |
  | `klav sandbox --help` y el `next` de `klav sandbox start` | Las opciones, los perfiles, el TTL, las líneas del *setup script*, cómo pasar el paquete al proveedor y el recordatorio de parar al terminar |
  | El `message` y el `next` de cada error `klav_*` de `klav-forward` (§10) | Qué decirle a la persona y qué hacer; llegan en cada respuesta, también a un agente sin la skill |
  | `klav mcp` | Nada nuevo |

- **Por qué no hay herramienta de MCP:** el paquete tiene que llegar al comando que crea el sandbox, y solo la forma `klav sandbox start … -- comando` lo mantiene fuera del contexto del modelo (E6.1). Una herramienta tendría que devolverlo o correr el comando del proveedor ella misma.
- **El emisor puede ser un programa o un agente.** §4 piensa en el lado servidor de T3 Code, que no lee skills. Esta parte de la skill es para un agente de un cliente (Claude Code en el Mac, por ejemplo) al que la persona hizo emisor (`klav proxy issuer add`, E6.2), y para el agente que trabaja dentro del sandbox.

#### E1.2 El texto
Tres cambios en `skill/SKILL.md`, en inglés como el resto del archivo:

1. **El `description` del *frontmatter*** también tiene que cargar la skill cuando la tarea habla de un sandbox. Si no, la sección nunca llega al modelo:

   ```yaml
   description: Use the person's Klav vault to log in to sites, run commands with API keys and write config files without ever seeing the secrets. Use whenever a task needs a password, API key, token, TOTP code, card or a `.env`/key file, needs credentials in a sandbox, VM, container or CI runner, or mentions Klav, `klav://` references, `klav.toml`, `klav sandbox` or `klav-forward`.
   ```

2. **Una línea en la introducción,** antes de la que manda a «If you are not connected to Klav yet», porque dentro de un sandbox esa sección llevaría al agente a registrar una llave de Klav allí:

   ```markdown
   Inside a sandbox, read [Sandboxes](#sandboxes) first: never connect to Klav there.
   ```

3. **La sección nueva,** entre «The rules» y «If you are not connected to Klav yet». Además, la lista final de comandos de la persona («Never run the person's commands») suma `klav proxy …`.

   ```markdown
   ## Sandboxes

   A sandbox (a disposable VM or container, such as one from Boat) is a
   machine the person does not control and others can copy. Never put a
   provider token or a Klav key in one: not in its environment, its files,
   its setup script, the provider's settings or the repository, not through
   `klav agent run`, `inject` or `reveal`, and not by asking the person to
   paste one. Klav's credential proxy adds the token to each call instead.

   - **Where the code runs decides.** On this machine, use
     `run_with_secrets` (or `klav agent run`). In a sandbox, CI or any
     machine that is not the person's, start a sandbox with Klav.
   - **Start one** with `klav sandbox start --label <purpose> --profile
     <name> -- <command that creates the sandbox>`. That command gets a
     one-time package in `KLAV_SANDBOX`: pass it only through the provider's
     secret mechanism, and never print it or write it anywhere else. The
     setup script runs only the lines `klav sandbox start` gives you,
     starting with `klav-forward up --daemon`; they hold no secrets.
   - **Stop it** when the work is done: `klav sandbox stop <id>`, delete the
     sandbox at the provider, and check `klav sandbox ls`.
   - **No proxy:** if `klav sandbox start` says the account has none, tell
     the person what they lose and how to set one up, as its message says,
     and stop. Never fall back to copying keys. If the code can run here,
     offer to run it here instead.
   - **Inside a sandbox** (`klav-forward status` answers), never connect or
     register with Klav. Errors arrive with a `Klav-Error` header (`error`,
     `message`, `next`): tell the person the `message` as it is and follow
     `next`, without retrying in a loop or looking for the token elsewhere.
   ```

**Tamaño:** unas 30 líneas, y la skill pasa de 103 a unas 135. Sigue por debajo de las 204 que tenía antes de adelgazar. Lo que no cabe va al `next` (E1.3): el TTL, las líneas exactas del *setup script*, cómo espera una aprobación dentro del sandbox (`klav-forward approval wait`) y qué hacer con cada error. La regla 4 de la skill («When the answer is pending») ya cubre las aprobaciones, con el comando que da el `next`.

Omar eligió esta forma de pasar el paquete (P4, E9): el entorno del comando que sigue a `--`. `--package-file` es para programas como T3 Code (E6.1), y la skill no lo nombra.

#### E1.3 Lo que dicen `--help`, los `next` y los errores
Lo que la skill deja de decir lo dice el binario, en inglés:

- **`klav sandbox start` sin proxy** (`proxy.mode = none`) sale con el error `klav_no_proxy`. Es lo que §13 manda decir:
  - `message`: «This Klav account has no credential proxy, so a sandbox can't use your API keys without copying them into it.»
  - `next`: «Tell the person this message, and that they can set up a proxy in the Klav app (Development › Sandboxes) or start with `klav proxy status`. Do not copy keys into the sandbox. If the code can run on this machine, offer to run it here with `run_with_secrets` or `klav agent run`.»
- **Un agente que no es emisor** recibe `klav_not_issuer`, con `next`: «Tell the person they can let <agent> start sandboxes with `klav proxy issuer add <agent>` in their own terminal, or in the Klav app. Do not run it yourself.»
- **Al empezar bien,** el `next` dice: «Put the setup lines in the sandbox's setup script as they are. When the work is done, run `klav sandbox stop <id>` and delete the sandbox at the provider.»
- **El proxy caído, la pausa y los límites del emisor** (`klav_proxy_unreachable`, `klav_agents_paused`, `klav_too_many_sandboxes`, `klav_profile_not_allowed`) salen con los códigos de salida estables que la skill ya explica (3 a 7) y su propio `next`.
- **Dentro del sandbox,** los errores de §10 no cambian. `klav_sandbox_revoked` y `klav_sandbox_expired` dicen en su `next` que solo la persona o el emisor pueden dar otro, y que el agente pare.

#### E1.4 Dentro del sandbox
El agente que trabaja dentro del sandbox no tiene por qué tener la skill: sus skills son las de la casa del sandbox, no las del Mac. Hoy le llegan el `message` y el `next` de cada error, que bastan para no reintentar en bucle. No le llega la regla de no conectarse a Klav ahí, ni la de no pedir que le peguen un token.

**Decisión (P6, Omar, 2026-11-09):** `klav-forward` lleva dentro la misma `skill/SKILL.md` (es texto, sin código de la bóveda), y `klav-forward up` la instala en `~/.claude/skills/klav/` y `~/.agents/skills/klav/` del usuario del sandbox si no hay una, y lo dice en su salida.
- **Con una skill que ya esté, se porta como la app de Mac con las copias de su registro (ADR 0033 §6)** (aclaración de P6, E9):
  - **una copia sin cambios de una versión anterior de la de Klav** (su SHA-256 es el de una versión de `PUBLISHED` más vieja que la que lleva `klav-forward`) se reemplaza (temporal y `rename`), y la salida lo dice;
  - **una copia editada, una que no es de Klav, la misma versión o una más nueva** no se toca: la deja como está y dice que no la instaló ahí.
- **Sin registro ni preguntas.** En el sandbox no hay registro de lo que escribió Klav (ADR 0033 §3.4) ni nadie a quien preguntar, así que la única copia que reemplaza es la que coincide byte a byte con una versión publicada: es texto de Klav que nadie cambió.

Las líneas del *setup script* que da `klav sandbox start` ya lo hacen. Es la casa del sandbox, que muere con él.

#### E1.5 Cuándo se publica
- **El texto llega en la capa 6,** cuando ya existen `klav sandbox start` (capa 5) y `klav-forward up` (capa 6). Antes, la skill describiría comandos que el binario no tiene, que es justo lo que el ADR 0033 E3.1 quiere evitar.
- **En esa capa:** versión nueva de la skill y su línea en `PUBLISHED`, y una prueba de que cada subcomando de `klav sandbox` y de `klav-forward` que nombra la skill existe en su `--help`, como la de `tools/list` (ADR 0033 E3.2). La app reemplaza las copias sin cambios y ofrece el *diff* en las editadas (ADR 0033 §6). Dentro del sandbox, `klav-forward up` solo reemplaza una copia sin cambios de una versión anterior de la de Klav, y nunca una editada ni una ajena (E1.4).
- **Este PR no toca `skill/SKILL.md`.**

### E2. «Sandboxes activos»: lo que ve la persona
#### E2.1 Cada fila

| Dato | De dónde sale (E3.3) | Cómo se muestra |
|---|---|---|
| Etiqueta | `sandbox.issued`, firmado por el proxy; la pone el emisor | Texto plano en una línea, recortado, entre comillas y marcado «según el emisor» (T136, T157), con el comienzo del ID del sandbox |
| Perfiles | `sandbox.issued` | `northflank`, `maple` |
| Emisor | `sandbox.issued` | El nombre del agente y el comienzo de su ID, con un enlace a su ficha |
| Vence | `sandbox.issued` | «en 6 h 12 min» |
| Última conexión | El latido del proxy | «hace 2 min, según el proxy». Sin un latido de los últimos 10 min, con la edad medida desde su `sent_at_ms` firmado (E3.3): «el proxy no da señales desde las 23:10». Con el proxy en pausa, «En pausa» (E3.3) |
| Último uso | El último `agent.access` del proxy con ese sandbox | «hace 5 min», con un enlace a la Actividad filtrada por ese sandbox |
| Estado | La cadena y el latido | Abajo |

**Estados:**

- **Esperando el reclamo:** hay `sandbox.issued` y no `sandbox.claimed`. Pasados 15 minutos, la fila añade «Nadie lo reclamó todavía»: puede que el sandbox no arrancara.
- **Activo:** reclamado, sin revocar y sin vencer. Debajo, «conectado» o «sin conexión desde hace 20 min» (a la hora sin conexión se revoca solo, §4).
- **Revocando…:** la persona lo revocó y el servidor lo guardó, pero el proxy aún no lo confirmó con su `sandbox.revoked`. Pasados 2 minutos: «Revocado en el servidor; el proxy aún no lo confirma» (E3.3).
- **En pausa:** con el proxy en pausa (la global o la suya), el proxy no puede registrar nada en el servidor y lo guarda para cuando se reanude (E3.3). Las filas dicen «En pausa» y, las que esperan al proxy, «se confirma al reanudar», en lugar de «el proxy aún no lo confirma» o «el proxy no da señales».
- **Revocado,** con el motivo: «Lo revocaste tú», «Lo paró el emisor» (`stop`), «Lo soltó el sandbox al apagarse» (`released`), «Quitaste o revocaste al emisor» (`issuer_removed`, Q-C), «Venció» o «Una hora sin conexión».
- **Señal de robo,** en rojo: `sandbox.revoked` con el motivo `theft`. Dice «Alguien reclamó este sandbox por segunda vez y Klav lo revocó. Si no fueron ni tú ni el emisor, alguien copió su entorno: Boat guarda sus variables». Ofrece «Ver actividad» y «Pausar al emisor». El texto que se publica dice «el proveedor del sandbox conserva sus variables», sin nombrar a Boat (Omar, 2026-11-17).

**Grupos:** las señales de robo arriba, hasta que la persona pulsa «Entendido»; luego «Activos» (esperando, activos y revocando); al final, «Terminados en las últimas 24 h», plegado.

#### E2.2 Las acciones
- **«Revocar»** en cada fila esperando o activa. Actúa al momento.
- **«Revocar todos»** arriba de la lista: revoca todos los sandboxes del proxy de la cuenta creados hasta ese momento, es decir, los que la cadena tiene antes de la revocación, sin contar con el reloj del dispositivo (alcance `all`, E3.3). Una sola confirmación en la misma hoja, sin Face ID ni Touch ID: dice cuántos, que corta el trabajo de todas esas conversaciones y que **los emisores pueden crear otros**. Para que no, la hoja ofrece «Pausar agentes» y el enlace a cada emisor, para pausarlo, quitarlo o revocarlo.
- **Pausar, quitar o revocar a un emisor** (Q-C, E9) corta sus sandboxes vivos en su llamada siguiente, porque el servidor exige en cada acceso que el emisor siga en el grant del proxy, sin pausa y sin revocar (E3.3):
  - **en pausa,** sus sandboxes reciben `klav_agents_paused` y vuelven a funcionar al reanudarlo, si no vencieron;
  - **quitado** (`klav proxy issuer remove`) **o revocado,** el proxy los revoca con el motivo `issuer_removed`.

  Por eso la señal de robo ofrece «Pausar al emisor»: corta también los otros sandboxes de ese emisor.
- **La pausa y la revocación** hacen cosas distintas. La pausa ya corta los sandboxes, porque el proxy y el emisor son agentes:

  | | «Pausar agentes» | «Revocar» | «Revocar todos» |
  |---|---|---|---|
  | Qué corta | Todas las llamadas de todos los agentes: cada sandbox recibe `klav_agents_paused` en la siguiente | Ese sandbox | Los sandboxes que la cadena tiene antes de la revocación |
  | Sandboxes nuevos | No: el servidor rechaza el `sandbox.issued` del proxy en pausa (E3.3) | Sí | Sí, salvo que se pause o revoque al emisor |
  | Vuelta atrás | Reanudar, con Face ID o Touch ID | No: el emisor da otro | No |
  | Pide | Nada | Nada | Una confirmación |

  «Pausar agentes» sigue siendo el botón del susto (ADR 0033 §7). «Revocar» es lo que se hace cuando ya se sabe qué sandbox sobra.

#### E2.3 Revocar no pide nada: decisión de Omar
- **Revocar no pide Face ID, Touch ID ni la contraseña maestra** (Omar, 2026-11-09), como pausar: solo quita acceso. No hay «reanudar» un sandbox: el emisor da otro.
- **Pero hay que firmar** (E3.3), y la identidad de la cuenta solo está disponible con la bóveda abierta. Igual que la pausa (ADR 0033 §7.3):
  - **en iOS,** la lista solo se ve con la app desbloqueada, así que revocar no pide nada más;
  - **en el Mac con `klavd` desbloqueado,** un clic firma y envía;
  - **en el Mac con `klavd` bloqueado y el proxy en este Mac,** la app se lo dice al proxy por el *socket* local (E3.5), que revoca al momento sin que nadie firme. La fila dice «Revocado en este Mac»;
  - **en el Mac con `klavd` bloqueado y el proxy en otro sitio,** no hay con qué firmar. El botón dice «Desbloquea para revocar», y la vía rápida es el iPhone. Desbloquear es el cerrojo de la bóveda, no una comprobación nueva.

### E3. De dónde sale la lista y cómo llega la revocación al proxy
#### E3.1 Lo que hay hoy
- **El estado de cada sandbox vive solo en el almacén del proxy** (§4). El servidor solo ve `sandbox.issued` y `sandbox.revoked`, que el proxy registra con una petición firmada (§9).
- **Pero el servidor ya está en el camino de cada llamada.** El proxy hace un `POST /v1/agent/access` firmado por cada petición que inyecta, declara el sandbox y nunca guarda en caché la autorización (§2). Por eso la pausa corta un sandbox en la llamada siguiente (`klav_agents_paused`, §10). Esta sección se apoya en eso.
- **`klav-client` ya guarda la cadena verificada** y solo pide lo nuevo (ADR 0033 §8.4). Mac e iOS la leen por `klav-ffi`.
- **Lo que falta:**
  - el reclamo, para separar «Esperando el reclamo» de «Activo»;
  - la última conexión;
  - una revocación que no venga del emisor;
  - que un emisor no vea ni pare los sandboxes de otro, que §4 no dice.

#### E3.2 Las opciones
- **(a) Por el servidor.** El proxy publica el ciclo de vida de cada sandbox como eventos firmados en la bitácora, más un latido firmado con la última conexión. La persona firma la revocación; el servidor la guarda, la aplica en cada acceso y el proxy la recoge.
- **(b) Directo al proxy.** Las apps abren un canal fijado con el proxy (su dirección y su huella ya están en la cuenta, §3) y se autentican con la identidad de la cuenta. Piden la lista y mandan la revocación. El servidor no se entera.
- **(c) Solo la bitácora.** La lista sale de la cadena y nadie revoca un sandbox suelto: para cortar, se pausa o se revoca al emisor o al proxy.
- **(d) (a), y además el *socket* local cuando el proxy corre en este Mac** (capa 11), para la lista en vivo y la revocación con `klavd` bloqueado.

| | Proxy en este Mac, dormido | Proxy inalcanzable (caído o sin red) | Servidor malicioso | Proxy malicioso | Lo que cuesta |
|---|---|---|---|---|---|
| **(a) Por el servidor** | La lista muestra lo último de la cadena y la edad del latido. La revocación queda en el servidor, y el proxy la recoge al despertar, antes de servir. Mientras duerme, ningún sandbox puede usarlo | La revocación vale al momento: el servidor rechaza el acceso de ese sandbox, y sin acceso no hay inyección | No puede inventar sandboxes ni motivos, porque los firma el proxy. Puede esconder lo posterior a la última cabeza firmada (riesgo 10), repetir un latido viejo (la app muestra su edad) y retener la revocación: la app no ve la confirmación del proxy y lo dice, y `verify` marca los accesos posteriores | Miente en sus eventos y en su latido, ignora la revocación y se queda con los valores que ya descifró. Solo sirve revocar el proxy y rotar los tokens (§18, riesgo 52) | Dos acciones nuevas en la tabla cerrada, un latido, una firma nueva con su vector y las comprobaciones del servidor |
| **(b) Directo al proxy** | Nada: ni lista ni revocación. Desde el teléfono no llega a un Mac detrás de NAT sin Tailscale en el iPhone | La revocación se pierde. Cuando el proxy vuelve, el sandbox sigue vivo hasta el TTL o la hora sin conexión | Queda fuera de la lista y de la revocación. Pero sigue en cada acceso (§2), y no sabe nada de la revocación, así que no puede ser segunda barrera | Igual que (a) | Una API para personas en un proxy expuesto a internet, la identidad de la cuenta en cada petición de las apps, y Tailscale en iOS para el proxy en el Mac |
| **(c) Solo la bitácora** | La lista, como (a), sin la última conexión. No se revoca un sandbox suelto | Igual | Como (a), para la lista | Igual que (a) | Casi nada, pero no hace lo que pidió Omar |
| **(d) (a) más el *socket* local** | Como (a). Con el Mac despierto, además, la lista en vivo y la revocación al momento, también con `klavd` bloqueado | Como (a) | Como (a) | Igual que (a) | (a), y un *socket* local en la capa 11 |

**Recomendación: (d), que Omar eligió el 2026-11-09** (P1, que en E9 es la opción (a)). El servidor ya autoriza cada llamada que inyecta (§2), así que una revocación guardada allí corta el sandbox en la llamada siguiente, aunque el proxy nunca se entere. Funciona desde el teléfono con el Mac dormido, que es el caso de Omar (respuesta 1). La bitácora hace que la lista se pueda verificar.

(b) falla justo cuando hace falta, con el proxy inalcanzable, y abre una API nueva en una máquina expuesta. Lo único que gana, que un servidor malicioso no pueda retener la revocación, (d) lo detecta: falta la confirmación del proxy. Contra un servidor malicioso, lo que de verdad sirve es rotar los tokens.

**Si el servidor está caído,** la revocación no sale: la app la guarda y la reintenta. Pero el proxy tampoco consigue acceso (`klav_server_unreachable`), así que ningún sandbox puede usar credenciales mientras tanto. Los dos fallos coinciden.

#### E3.3 Cómo funciona (d)
**La lista: la cadena y un latido**

- **Cuatro acciones del proxy en la tabla cerrada de `klav log verify`** (ADR 0030 §4), todas con su petición firmada **con cuerpo**:
  - `sandbox.issued` (ya en §9): el `sandbox_id`, el emisor, la etiqueta, los perfiles y `expires_at`. **El proxy la registra antes de devolver el paquete al emisor.** Si el servidor la rechaza, no hay paquete. El servidor la rechaza si el proxy o el emisor están en pausa o revocados, o si el emisor no está en el grant del proxy. Así, «Pausar agentes» y pausar o revocar a un emisor también impiden sandboxes nuevos;
  - `sandbox.claimed` (nueva): el `sandbox_id` y el SHA-256 de la llave del canal. **El proxy la registra antes de dar el secreto por gastado,** como `sandbox.issued`: si el servidor la rechaza (con el proxy en pausa, abajo) o no responde, el reclamo falla con `klav_agents_paused` o `klav_server_unreachable`, el secreto sigue sin gastar y `klav-forward` lo guarda en memoria y reintenta. Un segundo reclamo no es otro `claimed`, sino `sandbox.revoked` con `theft`;
  - `sandbox.revoked` (ya en §9), con el motivo: `stop` (lo paró el emisor), `ttl`, `inactivity`, `theft` y, nuevos:
    - `released`, cuando `klav-forward` suelta su propio sandbox al apagarse. Antes también era `stop`, y la app habría dicho «Lo paró el emisor» en los dos casos;
    - `issuer_removed`, cuando la persona quitó o revocó al emisor (Q-C);
    - `person`, con el `at` de la revocación de la persona a la que responde, o `person_local` si llegó por el *socket* local (E3.5);
  - `sandbox.store_reset` (nueva): la época de un almacén nuevo del proxy, `store_epoch` (abajo, en el latido).
- **El verificador las comprueba** como cualquier evento de agente (especificación §13.7): el método, la ruta, el cuerpo y la identidad del proxy, avalada por un `agent.granted` anterior. Un `claimed` o un `revoked` exige antes un `issued` del mismo sandbox y del mismo proxy, y cada `store_reset` trae una época que ese proxy no usó antes.
- **El latido.** El proxy manda `PUT /v1/agent/sandboxes/state`, una petición firmada con `{store_epoch, seq, sent_at_ms, sandboxes: [{id, connected, last_seen_at}]}`. Lo manda cada 5 minutos mientras tiene sandboxes vivos, cada 30 minutos sin ninguno, y además al conectarse o desconectarse uno, como mucho una vez por minuto.
  - **`sent_at_ms`** es la hora del proxy al firmarlo. La edad que muestra la app se mide desde ahí, no desde lo que diga el servidor, así que un latido viejo repetido se ve viejo. Uno con `sent_at_ms` más de 5 minutos en el futuro se descarta.
  - **`seq` vive en el almacén del proxy** (§4) y se guarda antes de mandar el latido, así que un reinicio del proxy nunca lo baja.
    - Nota del 2026-11-13: `seq` y la época viven en un archivo propio del proxy, junto al almacén y no dentro de él («Las preguntas abiertas de la capa 5a»).
  - **La época del almacén.** Si el almacén se pierde y la llave del proxy no (un volumen nuevo con la llave guardada aparte, o el almacén borrado en el Mac), `seq` volvería a empezar y los dispositivos rechazarían cada latido nuevo. Por eso cada almacén nuevo, también el primero, crea una época, `store_epoch` (16 bytes al azar), y el proxy registra `sandbox.store_reset` con ella antes de su primer latido. El latido la firma. El dispositivo solo acepta latidos con la época del último `sandbox.store_reset` de ese proxy en la cadena, y dentro de ella no deja bajar `seq`. Un latido de antes del reinicio, repetido después, lleva la época vieja y no vale. El orden de las épocas lo da la cadena verificada, no el servidor; si este esconde el último `store_reset`, la app ve un latido que no puede aceptar y dice que el proxy no da señales.
  - **El latido lento sin sandboxes vivos** existe para que la cabecera del panel (E4) no diga «el proxy no da señales» de un proxy vivo y quieto. Sin sandboxes vivos, la app solo lo dice pasados 40 minutos. Con el proxy en pausa no lo dice: dice «En pausa» (abajo).
  - El servidor guarda **solo el último** de cada proxy, con su firma, fuera de la cadena: un evento cada 5 minutos serían 288 al día que nadie necesita verificar uno por uno.
  - `GET /v1/sync` lo devuelve (`sandbox_state`). El dispositivo verifica la firma con la identidad del proxy que da su grant, rechaza un latido de otra época que la del último `sandbox.store_reset` y, dentro de esa época, un `seq` menor que el mayor que ya vio (como las marcas de agua contra el *rollback*, T7), y muestra su edad.

**La revocación: firmada por la cuenta y guardada en el servidor**

- **Mensaje:**

  ```
  tuple("klav/v1/sig/sandbox-revoke", account_id, proxy_id, alcance, u64_be(at_ms))
  ```

  - `proxy_id`: el `agent_id` del proxy de la cuenta (§3);
  - `alcance`: el `sandbox_id`, o `"all"`, que son todos los sandboxes de ese proxy cuyo `sandbox.issued` está en la cadena antes del `sandbox.revoke_requested` que escribe el servidor (abajo). **Lo decide el orden de la cadena, no `at_ms`:** el servidor acepta relojes a ±5 minutos, y un dispositivo con el reloj 3 minutos atrasado dejaría fuera justo los sandboxes más nuevos. `at_ms` sirve contra repeticiones y, con 5 minutos de margen hacia atrás, para dejar fuera los que ya vencieron (especificación §13.11).

  La codificación exacta, su sección de la especificación (§13.11, porque §13.9 es de la pausa y §13.10 del paquete `ksb1_`) y el vector en `docs/vectores/` van con el código, como hizo la pausa (ADR 0033 §7.3). La etiqueta vive en `klav-core`, como todas.
- **Firmada por la cuenta,** como la pausa y la revocación de un agente: la bitácora prueba que fue la persona, y el servidor no puede fabricarla. Sin Face ID, Touch ID ni contraseña (E2.3).
- **`POST /v1/sandboxes/revoke`** con `{proxy_id, scope, at, signature}`. El servidor comprueba la firma, que `at` esté a ±5 minutos de su reloj y que sea mayor que el de la última revocación del mismo alcance, como con la pausa. Escribe `sandbox.revoke_requested` (actor `person`, firma de la cuenta) en la cadena, en la misma transacción y con el cerrojo de la cuenta. Con `all`, ese evento lleva además la lista de los `sandbox_id` que abarca, sacada de la cadena con el mismo cerrojo, así que ningún `sandbox.issued` puede colarse entre la lista y el evento.
- **El servidor es la segunda barrera,** como en la pausa (ADR 0033 §7.2). Rechaza el `POST /v1/agent/access` del proxy que declara un sandbox:
  - con `403 sandbox_revoked` si el sandbox:
    - tiene un `sandbox.revoke_requested` propio, o está en la lista de uno con `all`;
    - tiene un `sandbox.revoked`;
    - no tiene `sandbox.issued`;
    - pasó su `expires_at`;
    - es de un emisor que ya no está en el grant del proxy o que está revocado (Q-C);
  - con `403 agents_paused` si su emisor está en pausa (Q-C). Al reanudarlo, sus sandboxes vuelven a funcionar si no vencieron, como cualquier pausa.

  También rechaza su `sandbox.claimed`. **Sin acceso no hay inyección: la revocación corta en la llamada siguiente aunque el proxy no se entere.** El proxy hace las mismas comprobaciones del emisor con su propio grant.
- **El proxy se entera de tres formas,** y en todas verifica la firma de la cuenta (cuya identidad fijó al emparejarse) antes de actuar:
  1. el `403 sandbox_revoked` del siguiente acceso;
  2. `GET /v1/agent/sandboxes/revocations?since=`, al arrancar y al despertar, **antes de servir**, y cada 30 segundos mientras tiene sandboxes vivos. Así corta lo que no pasa por un acceso en cada llamada: un *stream* MCP abierto o un canal quieto. Una revocación con `all` llega con su lista;
  3. en este Mac, el *socket* local (E3.5).

  Entonces cierra el canal, olvida la llave del canal y registra `sandbox.revoked` con `person`. Si lo que cambió es el emisor (quitado o revocado, que el proxy ve en su grant nuevo o en la respuesta del servidor), registra `issuer_removed`.
- **La confirmación.** La app dice «Revocando…» hasta ver en la cadena el `sandbox.revoked` del proxy. A los 2 minutos sin él, dice «Revocado en el servidor; el proxy aún no lo confirma», con la edad del latido. Con el proxy en pausa dice, en cambio, «En pausa; se confirma al reanudar» (abajo).
  - Si su propia revocación firmada no aparece en la cadena en la siguiente sincronización, avisa en rojo: «El servidor no registró tu revocación». Sigue reintentando y ofrece «Pausar agentes» y revocar el proxy.
  - `klav log verify` avisa de cada `agent.access` con `outcome: allow` de un sandbox después de su `sandbox.revoke_requested`, como hace con la pausa (ADR 0033 §7.6).
  - Con `all`, `klav log verify` comprueba además que la lista del evento sea exactamente la de los `sandbox.issued` de ese proxy que la cadena tiene antes, sin `sandbox.revoked` y con `expires_at` posterior al `at_ms` firmado menos 5 min (los que la persona ya revocó y el proxy aún no terminó entran, y también los que vencieron dentro de esa ventana; especificación §13.11). Así la hora del servidor no decide qué cubre. La firma de la cuenta no cubre la lista, porque la pone el servidor; la cadena sí.

**Con el proxy en pausa**

- **El servidor le rechaza toda petición firmada salvo `GET /v1/agent/me`** (ADR 0033 §7.1), sea la pausa global o la suya. No hace falta otra excepción en ese §7.1: lo que el proxy no puede registrar, sobre todo sus `sandbox.revoked` (vencimiento, inactividad, robo o `released`), y su último latido, lo guarda en su almacén, en orden, y lo manda al reanudarse.
- **Al reanudarse,** antes de servir, el proxy consulta primero las revocaciones (`GET /v1/agent/sandboxes/revocations`) y las aplica. Después manda lo que guardó.
- **Un reclamo en pausa se rechaza,** como un `sandbox.issued` (arriba): el proxy registra `sandbox.claimed` antes de dar el secreto por gastado (§5), y el servidor lo rechaza con `403 agents_paused`. Así no hay ningún `sandbox.claimed` que guardar. El secreto sigue sin gastar, y `klav-forward`, que recibe `klav_agents_paused`, reintenta: el reclamo que entra al reanudarse es el primero, no un segundo.
- **Un segundo reclamo en pausa,** de un sandbox reclamado antes, sí es robo: el proxy revoca el sandbox al momento y guarda su `sandbox.revoked` con `theft`. El servidor lo recibe al reanudarse, y el *push* `sandbox_theft` sale entonces.
- **Lo que muestra la app:** las filas dicen «En pausa» y, las que esperan al proxy, «se confirma al reanudar», en lugar de «el proxy aún no lo confirma» o «el proxy no da señales» (E2.1).

**Cada emisor, solo lo suyo**

- `klav sandbox ls` y `klav sandbox stop` del emisor llegan al proxy (§4) y solo ven los sandboxes cuyo `sandbox.issued` nombra a ese emisor. Un `stop` de un sandbox ajeno recibe la misma respuesta que uno que no existe.
- El agente de un sandbox no puede tocar otros: `klav-forward` no tiene `stop`. Puede soltar el suyo al apagarse, que es un `sandbox.revoked` con `released`, no con `stop`, para que la app no diga «Lo paró el emisor».

#### E3.4 Lo que aprende el servidor
- **Nada nuevo sobre credenciales:** el servidor sigue sin ver tokens ni cuerpos.
- **Metadatos nuevos:** cuándo se reclama cada sandbox y, con el latido, cuándo está conectado. La etiqueta, los perfiles y el emisor ya los veía en `sandbox.issued` (§9). Entran en los metadatos en claro de T13 (riesgo residual 61).

#### E3.5 El proxy en este Mac: la mitad local
- **Con el proxy en este Mac** (capa 11, un *LaunchAgent*), la app le habla por un *socket* Unix del mismo usuario, en modo 0600, como el de `klavd` (T32), con dos operaciones:
  - `sandboxes`, la lista en vivo con la conexión real;
  - `revoke`, de un sandbox o de todos.
- **Con `klavd` bloqueado,** la revocación llega al proxy al momento, sin firma. El proxy la registra como `sandbox.revoked` con `person_local`, y desde ese evento el servidor también rechaza el acceso del sandbox.
- **Cualquier proceso del mismo usuario puede usar el *socket*:** solo ve metadatos y solo quita acceso (riesgo residual 49 y riesgo 64).

> Nota de implementación del 2026-11-25 (capa 11):
>
> - **Sin ayudante propio.** El *LaunchAgent* (`dev.klav.proxy`) corre el `klav` del paquete con `argv[0]` `klav-proxy`: con ese nombre, `klav` es `klav-proxy` (`klav_proxy::cli::main`). Un `klav-proxy` aparte ponía el DMG por encima de los 25 MB del ADR 0027 §5; dentro de `klav` suma 1,54 MB sin comprimir y unos 0,72 MB comprimido ([macos.md](../macos.md) §11).
> - **El *socket*** es `<KLAV_HOME>/agents/<nombre>.sock` (0600, el directorio del usuario; `--control-socket RUTA` o `--no-control-socket`). Una línea de JSON por conexión, de 1 KiB como mucho y en 5 s, y una respuesta. El proxy comprueba el uid del par (las credenciales del par del *socket*) y el cliente, que el *socket* y su directorio son del usuario y que nadie más escribe en el directorio. Las operaciones y sus respuestas están en [api.md](../api.md) §8.14: `sandboxes` da también el puerto, los perfiles MCP y los fines sin mandar; `revoke` toma un ID o `"all"`.
> - **`revoke` es `stop` de la persona:** el fin entra en la cola de fines y en el almacén antes de responder, y el proxy deja de servir el sandbox al momento. Espera como mucho 5 s a que el servidor lo registre; la respuesta dice si llegó (`logged`). `all` termina los sandboxes vivos del almacén, no los arranques que aún no terminan; uno que termine después vive.
> - **El servidor acepta `person_local`** desde esta capa, solo como `{"reason":"person_local"}` (la fila «`person_local` en el servidor» de E9 lo fijaba hasta la capa que lo manda). El verificador de `klav log verify` ya lo aceptaba. Un servidor anterior responde `400`: el fin se queda en la cola y el proxy lo reintenta, sin servir el sandbox.
> - **`serve --if-registered`** sale con `0` sin proxy registrado en `KLAV_HOME`, si otro ya responde en el *socket*, o si el proxy está pendiente, revocado o su cuenta espera el borrado: el *LaunchAgent* (`KeepAlive` solo tras un fallo) no se relanza en bucle en un Mac sin proxy.
> - **El *plist* no lleva `--channel`:** en el Mac sirve `127.0.0.1:8790` (los clientes MCP locales, ADR 0049) y el *socket*. Que un sandbox llegue a este Mac pide una dirección que lo alcance, y Tailscale con llaves efímeras para el proxy de este Mac sigue aparte (el ADR 0042 lo resolvió para un proxy en un servidor). Hasta entonces, `klav-proxy serve --channel …` a mano.
> - **La CLI de la persona:** `klav proxy local status|revoke ID|--all|init` ([cli.md](../cli.md) §10), sin `klavd` y con la bóveda bloqueada. `init` corre `klav-proxy init` con el mismo binario.

### E4. Dónde va en cada app
**Mac.** Una fila nueva, «Sandboxes» (⌘7, libre), en Desarrollo, debajo de Agentes:

```
Desarrollo
  Agentes               ⌘3    «Pausar agentes» arriba de la lista
  Sandboxes             ⌘7    «Sandboxes activos», con el proxy arriba
  Actividad             ⌘5
  Clientes              ⌘6
  Entornos
```

- **Arriba, el proxy.** La fila «Proxy de credenciales» de §13 pasa a ser la cabecera de este panel: «Sin proxy», «Tu proxy: proxy.ejemplo.com» o «En este Mac», y la edad de su latido (sin sandboxes vivos, el proxy late cada 30 minutos, E3.3). Así hay una sola fila en la barra lateral. Sin proxy, el panel solo muestra esa cabecera, con la frase de lo que se pierde y «Configurar», sin lista vacía.
- **Debajo:**
  - las señales de robo, en rojo;
  - «Sandboxes activos», con «Revocar todos» arriba y «Revocar» en cada fila (E2);
  - «Emisores»: cada uno con sus perfiles, su TTL máximo y cuántos sandboxes puede tener a la vez (del grant del proxy), y el enlace a su ficha;
  - «Terminados en las últimas 24 h», plegado.
- **En pausa,** una línea arriba: «Agentes en pausa: ningún sandbox puede usar el proxy».
- **La señal de robo nunca se oculta,** esté como esté el interruptor «Desarrollo» (ADR 0033 E1): sale en rojo en el panel de la barra de menús, como los avisos de T131, y lleva a este panel.

**iOS.** Una sección «Sandboxes activos» en la hoja de Agentes (el botón del robot, ADR 0033 capa 6, PR #243), debajo de la tarjeta de la pausa y encima de la lista de agentes, con las mismas filas y acciones.
- La fila «Proxy de credenciales» de Ajustes (§13) lleva a la misma sección.
- Una señal de robo sale además como tarjeta roja arriba de la bóveda, como la de la pausa global, con «Ver» y «Entendido».

### E5. Avisos
- **La señal de robo va por el *push* que ya existe, pero la manda el servidor.** El proxy no puede mandar *push*: la llave de APNs vive en el servidor (`crates/klav-server/src/push.rs`). El camino:
  1. el proxy registra `sandbox.revoked` con `theft` (con el proxy en pausa, al reanudarse: E3.3);
  2. el servidor manda un *push* de un tipo nuevo, `sandbox_theft`, a los teléfonos de la cuenta. Como hoy, solo lleva la clave de idioma, el tipo y el ID del sandbox, nunca texto. Presupuesto: 10 por hora y cuenta;
  3. la app pide el evento, lo verifica en la cadena y solo entonces muestra «Señal de robo en "chat-123" (según el emisor)». Si no lo puede verificar, lo dice.
- **El Mac no tiene APNs** ([`macos.md`](../macos.md) §1). `GET /v1/events` gana el evento `sandbox` (`{sandbox_id}`, solo IDs, como los demás). La app de Mac, y la de iOS en primer plano, vuelven a leer la lista y, si es una señal de robo, muestran una notificación local.
- **Vencimientos (P3).** El dispositivo ya sabe `expires_at` por la cadena. Omar eligió (E9):
  - avisar 15 minutos antes, solo de los sandboxes usados en la última media hora, agrupados: «2 sandboxes vencen en 15 min; esas conversaciones perderán el acceso y el emisor puede dar otros»;
  - el servidor manda el *push* `sandbox_expiring`, porque conoce `expires_at` y el último acceso; el Mac lo programa en local.

  Un TTL no se alarga desde la app (lo fija el grant, §4), así que el aviso solo informa. Por eso se limita a los sandboxes en uso.

### E6. La CLI: lo que ve el emisor y lo que ve la persona
#### E6.1 El emisor (`klav sandbox …`, con la identidad del agente)
- **`klav sandbox start --label L --profile P… [--ttl 8h] -- <comando>`** corre el comando con `KLAV_SANDBOX` en su entorno. Redacta el paquete en su salida, como `klav agent run`, e imprime el ID, el vencimiento y las líneas del *setup script*.
  - El comando puede ser a su vez `klav agent run …`, para que la llave del proveedor del sandbox (la de la API de Boat) también llegue por Klav y no entre al contexto.
    > Nota del 2026-11-17: `klav agent run` necesita `inject` sobre un proyecto, y `klav agent register` pide no darle proyectos nunca a un emisor. Por decisión de Omar, en el uso diario la llave de Boat es del usuario del sistema del emisor en el anfitrión del proxy, y no llega por Klav (ADR [0042](0042-sandboxes-for-daily-use.md) §5 y §6).
  - **`--package-file RUTA`** escribe el paquete en un archivo nuevo 0600, para un programa como T3 Code que lo pasa por una API y luego borra el archivo.
  - **`--json`** devuelve `{sandbox_id, label, profiles, expires_at, setup, next}` y **nunca el paquete** (P4). §4 decía que `--json` lo devolvía. Pero un agente que lee esa salida mete el paquete en el contexto del modelo y en los registros de su proveedor (T172).
  - **Esto evita las fugas por descuido, no a un emisor que quiera el paquete.** Un agente emisor controla el comando que sigue a `--`: puede imprimir `$KLAV_SANDBOX` transformado, o usar `--package-file` y leer el archivo, y la redacción no es un canal sellado (ADR 0030 §2). Puede incluso reclamar el paquete él mismo y usar el proxy con esos perfiles, sin que salte la señal de robo, porque es el primer reclamo. Contra un emisor así, lo que limita es lo que la persona le concedió: sus perfiles, `max-live`, el TTL y las aprobaciones (T172).
- **`klav sandbox ls [--json]`**: solo los suyos, en vivo, preguntando al proxy:

  ```
  $ klav sandbox ls
  ID        LABEL      PROFILES           EXPIRES     LAST SEEN   STATE
  3f9a1c2e  chat-123   northflank,maple   in 6h 12m   2 min ago   active
  b71d04aa  chat-124   railway            in 7h 58m   -           waiting for claim
  ```

- **`klav sandbox stop <id> | --all`**: solo los suyos.

#### E6.2 La persona (`klav proxy …`)
§14 ya separa los comandos de la persona (`klav proxy …`) de los del emisor (`klav sandbox …`). Lo que eligió Omar (P5, E9) sigue esa línea:

- **`klav proxy sandboxes [--ended] [--json]`**: todos los sandboxes del proxy de la cuenta, de todos los emisores, sacados de la cadena y del latido:

  ```
  $ klav proxy sandboxes
  Proxy: proxy.example.com (heartbeat 2 min ago)

  ID        LABEL (per the issuer)  PROFILES          ISSUER               EXPIRES    LAST SEEN  STATE
  3f9a1c2e  "chat-123"              northflank,maple  t3-code (a41c…)      in 6h 12m  2 min ago  active
  b71d04aa  "chat-124"              railway           t3-code (a41c…)      in 7h 58m  -          waiting for claim
  9c02e5f1  "deploy"                northflank        claude-code (77e0…)  -          -          theft signal (revoked 10:42)

  Verified up to event #4812; 3 newer events not verified yet.
  ```

- **`klav proxy sandboxes revoke <id> | --all [--wait]`**: firma con la identidad de la cuenta por `klavd`, sin Touch ID (E2.3). Con `klavd` bloqueado pide desbloquear, como cualquier comando de la persona. Con `--wait`, espera la confirmación del proxy.
- **`klav proxy status`** suma una línea: «3 active sandboxes (`klav proxy sandboxes`)».
- **El paso que faltaba: hacer emisor a un agente.** §4 dice que la persona aprueba al emisor, pero §14 no dice cómo se marca un agente como emisor ni con qué límites, y la skill necesita nombrarlo (E1.3). Con P5:
  - `klav proxy issuer add <agente> --profile … [--max-ttl 8h] [--max-live 3]` y `klav proxy issuer remove <agente>`;
  - piden Touch ID o Face ID, porque dan acceso: firman un grant nuevo del proxy y uno del emisor, con la dirección y la huella del proxy (§3);
  - **`klav proxy issuer add` avisa de `inject`** (Q-D, E9). `inject` está en `allow` por defecto (diseño §5.2, ADR [0006](0006-semantica-de-politicas.md) §1), y un emisor con `inject` sobre el token de un proveedor puede pasárselo al comando que crea el sandbox (`klav agent run -- …`), que es justo lo que el sandbox evita (T171). Si la política de ese agente deja `inject` en `allow`, el comando lo dice y ofrece ponerlo en `ask` para ese agente, en el grant del emisor que ya firma. Así la tarjeta muestra el comando antes de cada `inject`. La persona puede dejarlo como está; la app avisa y ofrece lo mismo;
  - `klav proxy issuer remove` y revocar al emisor cortan sus sandboxes vivos en su llamada siguiente (Q-C, E2.2);
  - en las apps, va junto a «Usar desde sandboxes» (capa 4), y «Emisores» (E4) lo muestra.
- **Lo que el agente nunca corre,** porque es de la persona: `klav proxy grant`, `klav proxy use`, `klav proxy issuer …` y `klav proxy sandboxes revoke`. La skill lo dice (E1.2).

### E7. Amenazas
El modelo de amenazas, §5.17, gana **T168–T173 y los riesgos residuales 61–64**, «aceptado, pendiente de implementar» desde que Omar aceptó la enmienda (2026-11-09). Siguen a los del ADR 0037 (T162–T167 y los riesgos 57–60, PR #235).

| ID | Amenaza | Mitigación |
|---|---|---|
| T168 | Un servidor malicioso muestra una lista falsa o vieja: esconde un sandbox vivo, da por revocado uno que no lo está o repite un latido viejo | El ciclo de vida sale de eventos firmados por el proxy en la cadena verificada, que el servidor no puede fabricar; solo puede omitir lo posterior a la última cabeza firmada (riesgo 10). El latido va firmado, con un `seq` que el proxy guarda en su almacén y el dispositivo no deja bajar, y un `sent_at_ms` firmado del que la app saca su edad. Un sandbox solo sale como revocado con el `sandbox.revoked` del proxy. Riesgo residual 61 |
| T169 | Una revocación no llega al proxy: un Mac dormido, un proxy caído o sin red, o un servidor que la retiene | La revocación, firmada por la cuenta, se guarda en el servidor, que rechaza el acceso por llamada (§2) de ese sandbox: sin acceso no hay inyección. El proxy pide las revocaciones antes de servir y cada 30 s, y verifica la firma. La app dice «Revocando…» hasta ver la confirmación y avisa si su revocación no está en la cadena. En este Mac, el *socket* local. Riesgo residual 62 |
| T170 | Un agente revoca o para sandboxes ajenos: un emisor los de otro, el agente de un sandbox los de otro, o un proceso del Mac todos | El proxy solo deja a un emisor ver y parar los suyos, y responde igual a uno ajeno que a uno que no existe. `klav-forward` solo suelta el suyo. La revocación de la persona va firmada por la cuenta, pero no pide presencia (decisión de Omar), y el *socket* del proxy en el Mac la acepta sin firma. Solo quita acceso, y queda en la bitácora. Riesgo residual 64 |
| T171 | La skill, alterada o mal leída, lleva al agente a poner un token o una llave de Klav en el sandbox (`reveal` para pegarlo, `klav agent run` hacia el comando que crea el sandbox, registrarse dentro, pedirle a la persona que lo pegue, copiar llaves sin proxy) | La skill no es una barrera (T132). Frenan la política (`reveal` en `deny` por defecto), el grant del proxy (`proxy` sin `reveal`, `inject` ni `fill`, §2), un `klav-forward` sin código de la bóveda y el `next` de cada error. `inject` está en `allow` por defecto, así que `klav proxy issuer add` avisa y ofrece ponerlo en `ask` para ese agente (Q-D); solo entonces la tarjeta muestra el comando antes de cada `inject`. Riesgo residual 63 |
| T172 | El paquete `ksb1_` entra al contexto del modelo y a los registros del proveedor del LLM, porque un agente lee la salida de `klav sandbox start` | `--json` no lleva el paquete: va solo al entorno del comando de `--`, con su salida redactada, o a un archivo nuevo 0600 (E6.1). Eso evita las fugas por descuido, no a un agente emisor que quiera el paquete: controla el comando de `--` y puede sacarlo transformado, leer el archivo o reclamarlo él mismo, sin señal de robo. A ese lo limitan sus perfiles, `max-live`, el TTL y las aprobaciones. Si el paquete se filtra de otro modo, sirve una sola vez, y el reclamo de otro dispara la señal de robo (T147) |
| T173 | Avisos falsos o en ráfaga: el servidor manda señales de robo o vencimientos que no pasaron, o tantos que la persona deja de mirarlos | El *push* no lleva texto; la app solo muestra la señal de robo con un `sandbox.revoked` (`theft`) verificado. Presupuesto por hora y tipo; los vencimientos, agrupados y solo de sandboxes en uso (E5) |

**Riesgos residuales nuevos:**

- **61. La lista depende del servidor para estar al día** (T168). Un sandbox vivo puede no salir hasta que se verifique la cadena, y uno desconectado puede parecer conectado mientras dure la edad del latido. El latido le dice al servidor cuándo se conecta cada sandbox.
- **62. Contra un servidor y un proxy maliciosos, revocar no basta** (T169). El proxy ya tiene los valores descifrados. La app solo puede decir que no llegó la confirmación; sirve revocar el proxy y rotar los tokens (§18, riesgo 52).
- **63. Un agente con `inject` sobre el token de un proveedor puede pasárselo a un sandbox** (T171), con `klav agent run -- <comando que crea el sandbox>`. `inject` está en `allow` por defecto: lo frena la tarjeta de `ask` solo si la persona aceptó ponerlo en `ask` para ese agente cuando `klav proxy issuer add` se lo ofreció (Q-D). Si no, solo queda la skill, que no es una barrera.
- **64. Revocar no pide presencia** (T170, decisión de Omar). Otro proceso del mismo usuario, con `klavd` desbloqueado o con el *socket* del proxy en el Mac, puede revocar sandboxes. Solo quita acceso, como la pausa (riesgo 49). Por `klavd`, la bitácora lo atribuye a la persona, porque firma su identidad; por el *socket* local solo firma el proxy (`person_local`), y la bitácora dice que llegó por el *socket* de este Mac, no quién lo pidió.

### E8. Plan por capas y consecuencias
**Capas** (las de arriba, con lo que suma la enmienda):

- **Capa 1:** esta enmienda y el modelo de amenazas, en su propio PR de documentos.
- **Capa 4,** el ajuste de la cuenta y la concesión: más `klav proxy issuer add|remove`, con el aviso de `inject` y la oferta de ponerlo en `ask` (Q-D), y «Emisores» junto a «Usar desde sandboxes» en las apps (E6.2).
- **Capa 5,** el emisor: más
  - `sandbox.claimed`, registrado antes de dar el secreto por gastado, y los motivos `person`, `released` e `issuer_removed` en la tabla cerrada;
  - `sandbox.issued` registrado antes de dar el paquete;
  - `ls` y `stop` solo con los propios;
  - `klav sandbox start -- comando` y `--package-file`, y `--json` sin el paquete (E6.1);
  - los errores de `klav sandbox start` de E1.3 (`klav_no_proxy`, `klav_not_issuer`, `klav_too_many_sandboxes` y `klav_profile_not_allowed`), con su `message`, su `next` y su código de salida.
- **Capa 5a (nueva), la persona:**
  - la firma `klav/v1/sig/sandbox-revoke` con su vector (especificación §13.11);
  - `POST /v1/sandboxes/revoke` y `sandbox.revoke_requested`, con la lista de sandboxes de un `all` sacada del orden de la cadena;
  - el servidor como segunda barrera (`403 sandbox_revoked`, y `403 agents_paused` con el emisor en pausa), que también exige que el emisor siga en el grant del proxy y sin revocar (Q-C), y los avisos de `verify`;
  - `GET /v1/agent/sandboxes/revocations`;
  - el latido (`PUT /v1/agent/sandboxes/state`, con `sent_at_ms`, `store_epoch` y el `seq` guardado en el almacén del proxy, también sin sandboxes vivos, y `sandbox_state` en `GET /v1/sync`), y `sandbox.store_reset`;
  - lo que el proxy guarda en pausa y manda al reanudarse, con el reclamo rechazado en pausa;
  - la lista en `klav-client` y `klav-ffi`;
  - `klav proxy sandboxes [revoke]`;
  - los *push* `sandbox_theft` y `sandbox_expiring`, y el evento `sandbox` de `GET /v1/events`.
- **Capa 6,** `klav-forward`: más la parte de los sandboxes en la skill (E1), con versión nueva y su prueba, y `klav-forward up` que la instala en el sandbox si no hay una y reemplaza solo una copia sin cambios de una versión anterior de la de Klav, nunca una editada ni una ajena (P6 con su aclaración, E1.4); y el motivo `released` al soltar su sandbox.
- **Capa 6a (nueva):** «Sandboxes activos» en la app de Mac (E4), con las capturas en `macos.md`.
- **Capa 6b (nueva):** «Sandboxes activos» en iOS (E4), con las capturas en `ios.md`.
- **Capa 11,** el proxy en el Mac: más el *socket* local (E3.5).

**Consecuencias de la enmienda:**
- **Formatos:** la etiqueta `klav/v1/sig/sandbox-revoke` (especificación §13.11, con vectores); `sandbox.claimed`, `sandbox.revoke_requested` (con la lista de un `all`) y `sandbox.store_reset` en la tabla cerrada de §13.7, y los motivos `person`, `person_local`, `released` e `issuer_removed` de `sandbox.revoked`; el cuerpo firmado del latido, con `store_epoch`, `seq` y `sent_at_ms`. Un `klav log verify` anterior falla ante una cadena con las acciones nuevas, como pasó con la pausa: la CLI, `klavd`, la app de Mac y la de iOS se publican a la vez.
- **Protocolo:**
  - las rutas `POST /v1/sandboxes/revoke`, `GET /v1/agent/sandboxes/revocations` y `PUT /v1/agent/sandboxes/state`;
  - `sandbox_state` en `GET /v1/sync`;
  - el error `403 sandbox_revoked`, y `403 agents_paused` también por la pausa del emisor (Q-C);
  - los errores que el proxy le da al emisor: `klav_not_issuer`, `klav_too_many_sandboxes` y `klav_profile_not_allowed` (E1.3);
  - el evento `sandbox` de `GET /v1/events`;
  - los *push* `sandbox_theft` y `sandbox_expiring`.
- **CLI:** `klav proxy sandboxes [revoke]`, `klav proxy issuer add|remove` (con el aviso de `inject`, Q-D), `--` y `--package-file` en `klav sandbox start`, y sus errores `klav_no_proxy`, `klav_not_issuer`, `klav_too_many_sandboxes` y `klav_profile_not_allowed`, con los códigos de salida estables del 3 al 7 (E1.3).
- **`klav-forward`:** lleva la skill dentro, la instala si no hay una y solo reemplaza una copia sin cambios de una versión anterior de la de Klav (P6, E1.4).
- **El tipo `0x23`** para la llave de un elemento compartida del §2, en lugar del `0x22` (E10).
- **La skill:** el *frontmatter*, una línea en la introducción y la sección «Sandboxes» (E1), en la capa 6.
- **Sin dependencias nuevas.** La firma usa la identidad Ed25519 de la cuenta y las primitivas de siempre, en `klav-core`.
- **Docs:** `api.md`, `cli.md`, `macos.md`, `ios.md`, la especificación y el modelo de amenazas (§5.17).

### E9. Preguntas para Omar y su respuesta
**Respondidas el 2026-11-09.** Omar eligió la opción recomendada, la (a), en las seis, y con eso aceptó la enmienda. Antes había decidido que revocar no pide Face ID, Touch ID ni la contraseña maestra, como pausar (E2.3).

#### Respuesta de Omar (2026-11-09)
| # | Respuesta |
|---|---|
| P1 | **(a):** la lista y la revocación van por el servidor, más el *socket* local cuando el proxy corre en este Mac. La lista sale de la bitácora y de un latido firmado del proxy. La revocación la firma la cuenta y la aplica el servidor en la llamada siguiente del sandbox (E3.3, E3.5). Es la opción (d) de E3.2 |
| P2 | **(a):** en el Mac, una fila «Sandboxes» (⌘7) en Desarrollo, con el proxy arriba; en iOS, una sección en la hoja de Agentes. La señal de robo sale arriba de la bóveda (E4) |
| P3 | **(a):** la señal de robo avisa siempre. Un vencimiento avisa 15 minutos antes, solo de los sandboxes usados en la última media hora, y agrupados (E5) |
| P4 | **(a):** el paquete `ksb1_` nunca va en `--json`. Va al entorno del comando que sigue a `--`, o a un archivo nuevo 0600 con `--package-file`. La skill pide `--` (E1.2, E6.1) |
| P5 | **(a):** la persona usa `klav proxy sandboxes [revoke <id> \| --all]`, sin Touch ID. El emisor usa `klav sandbox start\|stop\|ls` y solo ve los suyos. `klav proxy issuer add\|remove` pide Touch ID, o Face ID en el iPhone (E6) |
| P6 | **(a):** `klav-forward up` instala la misma skill en `~/.claude/skills` y `~/.agents/skills` del sandbox cuando no hay una, y lo dice. Nunca pisa una skill que ya esté (E1.4). Aclarado abajo |

#### Tras la revisión de la enmienda (2026-11-09)
La revisión de la enmienda dejó dos preguntas, que Omar respondió con la opción recomendada, y una aclaración de P6.

| # | Respuesta |
|---|---|
| Q-C | **(a):** quitar, pausar o revocar a un emisor corta sus sandboxes vivos en su llamada siguiente. El servidor exige en cada acceso que el emisor siga en el grant del proxy, sin pausa y sin revocar (E2.2, E3.3) |
| Q-D | **(a):** `klav proxy issuer add` avisa y ofrece poner `inject` en `ask` para ese agente, porque está en `allow` por defecto (E6.2, T171, riesgo 63) |
| P6, aclaración | «Nunca pisa una skill que ya esté» se lee como el ADR 0033 §6: `klav-forward up` reemplaza solo una copia sin cambios de una versión anterior de la skill de Klav, y nunca toca una editada ni una que no sea de Klav (E1.4). La primera lectura, que no reemplazaba ni una copia sin cambios, dejaba en el sandbox una skill vieja que la app de Mac sí habría puesto al día |

**Nota del 2026-11-17 sobre Q-D.** E6.2 dice que, con `inject` en `ask`, «la tarjeta muestra el comando antes de cada `inject`», y lo repiten T171 (en E7 y en el modelo de amenazas) y el riesgo residual 63. No es así: una aprobación no lleva comando, directorio de trabajo ni archivo de destino (`ApprovalRequest` en `crates/klav-proto/src/agent.rs`), y su destino es la versión del grant, el permiso, la bóveda, el proyecto, el elemento y el dominio (`target_key` en `crates/klav-server/src/routes/agent_access.rs`). Lo que `--inject-ask` da hoy es que cada `inject` de ese agente pregunte, con el agente, el elemento y el motivo. El texto de E6.2 y de E7 se queda como se escribió; T171 y el riesgo 63 del modelo de amenazas ya dicen lo que hace el software, y la tarjeta con el comando, cifrado para los dispositivos de la persona y atado a la aprobación, es el [ADR 0041](0041-presence-for-values-and-the-inject-card.md) §5, aceptado el 2026-11-17 y sin construir. La respuesta (a) a Q-D sigue en pie.

#### Durante la capa 5a (2026-11-10)
La primera parte de la capa 5a se hizo sin migración. Lo que falta (E8) necesita tablas nuevas y rompe a los clientes de antes, y Omar respondió las dos cosas el 2026-11-10.

| # | Respuesta |
|---|---|
| Migración 0019 | **Aprobada:** cinco tablas nuevas y vacías con sus índices, en SQLite y en Postgres: `sandbox_revocations`, `sandbox_person_revoked`, `sandbox_heartbeats`, `sandbox_store_epochs` y `sandbox_pushes`. No lee ni reescribe nada de lo que ya existe. Un solo PR toca el archivo, y llega a `main` en un solo *squash* junto con cualquier arreglo de su revisión. La prueba de borrar una cuenta lista las tablas nuevas, y cada *push* nuevo lleva texto de respaldo, para que una app de iOS anterior nunca muestre una llave en bruto. Va después de la capa 6, que no la necesita |
| Clientes de antes de la 5a | **Ruptura aceptada:** un cliente compilado antes de la capa 5a falla `klav log verify` en las cuentas con sandboxes. Rechaza como alterado un `agent.access` cuyo cuerpo nombra un `sandbox`, lo que ocurre desde la capa 6, y muestra los nombres en bruto de los eventos de sandbox nuevos. El DMG y las apps se publican después de la 5a, y Omar pone al día todos sus dispositivos antes de usar sandboxes |

#### Durante la capa 6 (2026-11-10)
La revisión de la capa 3 dejó abierta la redacción como oráculo (T149). Omar la respondió el 2026-11-10.

| # | Respuesta |
|---|---|
| Redacción (T149) | **Solo el valor entero:** el `Redactor` del proxy reemplaza el valor inyectado completo, tal cual y en las codificaciones que ya cubre, nunca un trozo de 12 caracteres. Sigue contando, por perfil, los trozos que encuentra: un sandbox nunca lo nota (ni en la respuesta, ni en una cabecera, ni en un error, ni en un tiempo que valga la pena medir), y la persona lo ve en la línea del registro y en `klav-proxy status`. Un programa de la misma máquina, con el mismo usuario que el proxy, sí puede leer esas cuentas (nota del 2026-11-11, revisión de #310). Una adivinanza del valor entero sí se nota, porque se reemplaza: el proxy es para valores de mucha entropía. Costo aceptado: un trozo real del token que un servicio devuelva por accidente pasa. Va en su propio PR, antes del que deja `klav-forward up` listo para usarse |

#### El latido de la capa 5a (2026-11-13)
El verificador del latido fija en cada dispositivo tres cosas que E3.3 no nombraba. Cambiar cualquiera después pide otra ronda de dispositivos. Omar las confirmó el 2026-11-13.

| # | Respuesta |
|---|---|
| Ruta de la época | **Aprobada:** `POST /v1/agent/sandboxes/epochs` con el cuerpo `{store_epoch}` y nada más; `sandbox.store_reset` sin `outcome` |
| Tope del latido | **Aprobado:** como mucho 100 sandboxes por latido (`MAX_HEARTBEAT_SANDBOXES`). Un dispositivo lee un latido con más como «no es un latido», así que subir el tope pide otra ronda de dispositivos |

#### Las preguntas abiertas de la capa 5a (2026-11-13)
Los PRs de la capa 5a dejaron preguntas abiertas. Omar las respondió el 2026-11-13: «vamos con tus recomendaciones». Las marcadas **Fijo** quedan fijas con la ronda de dispositivos; cambiarlas después pide otra. Las demás son valores por defecto que siguen siendo baratos de cambiar.

| # | Respuesta |
|---|---|
| `person_local` en el servidor | **Fijo:** el servidor sigue rechazando un fin `person_local` con `400`, con cualquier forma de cuerpo y sin registrar nada, hasta la capa que lo manda (el *socket* local del proxy en el Mac, E3.5) |
| La hora firmada en «Revocar todos» | **Fijo:** la lista de un `all` sigue siendo la de los sandboxes que la cadena emitió antes de la revocación, sin terminar y sin vencer a la hora firmada (`at`), con el margen del reloj; el verificador la rehace con la misma regla, sin ninguna hora que elija el servidor (especificación §13.11) |
| El reenviador al vencer y ante `SIGTERM` | **Valor por defecto, aceptado:** al vencer el sandbox, `klav-forward` no sale solo: lo anota en su registro y sigue escuchando, y cada herramienta recibe `401 klav_sandbox_expired` con su `next`. `SIGTERM` lo para sin soltar el sandbox; solo `klav-forward down` lo suelta. No hay nada que construir |
| La lista de `all` frente al almacén del proxy | **Valor por defecto, aceptado:** la comprobación de tolerancia entre la lista que da el servidor y el almacén del proxy, cuando se construya, solo avisa: no bloquea ni corta nada. No va en esta pila |
| Quién llama a las rutas del latido | **Fijo:** sigue la regla de hoy: un agente activo y no en pausa de la cuenta cuyo grant, firmado por la cuenta, tiene perfiles del proxy o emisores (si no, `403 forbidden`). Una declaración firmada que nombre al proxy queda para después de la primera prueba real |
| Dónde vive `seq` | **Valor por defecto, aceptado:** el proxy guarda la época y el último `seq` en su propio archivo, `<home>/agents/<nombre>.sandbox-heartbeat`, junto al almacén y no dentro de él. Se aparta de E3.3, que los pone en el almacén: así el formato del almacén no cambia, y los dos archivos se mueven juntos |
| El cuerpo de las rutas del latido | **Aprobado:** `POST /v1/agent/sandboxes/epochs` y `PUT /v1/agent/sandboxes/state` toman el cuerpo solo como objeto JSON. La forma de arreglo, que el lector de JSON también acepta, es un `400`, y no se guarda ni se registra nada: el verificador de los dispositivos rechaza un `sandbox.store_reset` con esa forma |
| Ante un `409` del latido | **Valor por defecto, aceptado (2026-11-15):** el proxy empieza una época nueva y nunca repite un `seq`; un intento manda como mucho dos `sandbox.store_reset` y un latido. Es lo que hace el proxy, no un formato, así que sigue siendo barato de cambiar |
| Los tres archivos JSON del proxy | **Decidido (2026-11-15):** `<nombre>.sandbox-heartbeat`, `.sandbox-store` y `.sandbox-channels` no siguen la regla de los formatos binarios con versión, especificación y vectores. Son JSON con un `v`, no guardan llaves ni secretos (solo resúmenes `SHA-256`: el del secreto de cada sandbox y el de cada llave del canal) y los describe [api.md](../api.md) §8.9 y §8.10 |
| `sandbox-marks.bin` | **Fijo (formato cambiado por Omar el 2026-11-15, abajo):** la marca de agua del latido vive en su propio archivo sellado (propósito `sandbox-marks`), `{v: 1, marks: [{proxy, store_epoch, epoch_seq, seq}]}`, una marca por proxy; se lee solo con `v == 1` exacto y sin otros campos (confirmado por Omar el 2026-11-15), y un formato posterior conserva el propósito, el sobre y un `v` entero arriba. Un latido de otra `v` cuenta como «sin señales», nunca como alteración. Los umbrales de «callado» (10 y 40 min), los estados de la lista y su orden siguen siendo baratos de cambiar |
| Un proxy que el servidor no lista | **Fijo:** si el proxy que nombra el ajuste cifrado no está en `GET /v1/agents`, la lista falla con `ClientError::Security`; no se muestra con una marca de «no verificado» (`proxy.unverified`) |
| La marca entre épocas | **Decidido (2026-11-15):** la marca nunca vuelve a una época anterior. Cada una lleva `epoch_seq`, la posición en la cadena del `sandbox.store_reset` de su época, y la de otra época solo la reemplaza si es de una época posterior a la guardada; en un empate se queda la guardada. El archivo sigue en `v: 1`: ninguna versión publicada escribió el formato sin `epoch_seq` |
| Preferencias que no se leen | **Decidido (2026-11-15):** si el dispositivo no puede leer las preferencias, o dos elementos no coinciden, la lista no falla: da las filas de la cadena con `proxy` vacío y un aviso. Un error de seguridad de la cadena sigue haciéndola fallar, y también unas preferencias que escribió un agente (lo de antes; no lo decidió Omar) |
| `sandbox_revoke` en el *socket* de `klavd` | **Decidido (2026-11-15):** la petición lleva siempre `scope`: `"all"` o el ID de un sandbox. Una sin él, o con otra cosa, es un `bad_request` y no revoca nada |
| Lo que la versión no conoce | **Decidido (2026-11-15):** el estado de un sandbox, su motivo de fin y el «sin señales» del proxy tienen un caso «desconocido» para lo que mande un `klavd` más nuevo, también en los tipos de las dos apps. Falla cerrado donde se lea: un estado desconocido nunca cuenta como terminado, nunca sale de la cuenta de los vivos y nunca hace que el silencio del proxy parezca normal |
| Un latido que retrocede | **Decidido (2026-11-16):** un latido de la época actual con un `seq` menor que la marca de este dispositivo es un aviso de seguridad, no un fallo. No cuenta: el proxy sale «sin señales», con el motivo, y la marca no se mueve. La lista, que sale de la cadena, se muestra igual, y la CLI no sale con 3 por él. `klav proxy sandboxes` y `klav proxy status` lo dicen en la misma línea, «security warning». Un latido con el mismo `seq` que la marca no retrocede: es el mismo latido otra vez. Una cadena alterada y unas preferencias que escribió un agente siguen saliendo con 3 |

#### Las preguntas
Cada pregunta se podía responder sola. La primera opción era la recomendada.

| # | Pregunta | Opciones |
|---|---|---|
| P1 | ¿Cómo llegan la lista a las apps y la revocación al proxy? (E3) | **(a) Por el servidor, más el *socket* local cuando el proxy es este Mac: la lista sale de la bitácora y de un latido firmado del proxy, y la revocación va firmada por la cuenta y la aplica el servidor en la llamada siguiente (Recomendado)**<br>(b) Igual que (a), pero sin latido: «Último uso» de la bitácora en lugar de «Última conexión», sin formato nuevo para el latido<br>(c) Directo al proxy por un canal fijado, con la identidad de la cuenta y sin nada nuevo en el servidor<br>(d) Solo la bitácora: se ve la lista, pero no se revoca un sandbox suelto; para cortar, se pausa o se revoca al emisor o al proxy |
| P2 | ¿Dónde va «Sandboxes activos»? (E4) | **(a) En el Mac, una fila «Sandboxes» (⌘7) en Desarrollo, con el proxy de §13 arriba; en iOS, una sección en la hoja de Agentes, y la señal de robo arriba de la bóveda (Recomendado)**<br>(b) En el Mac, una sección dentro de Desarrollo › Agentes; en iOS, como (a)<br>(c) En el Mac y en iOS, dentro de «Proxy de credenciales» (en iOS, en Ajustes) |
| P3 | ¿Qué avisa con una notificación? (E5) | **(a) La señal de robo siempre, y el vencimiento 15 minutos antes, solo de los sandboxes usados en la última media hora, agrupados (Recomendado)**<br>(b) La señal de robo y todos los vencimientos<br>(c) Solo la señal de robo; los vencimientos, solo en la lista |
| P4 | ¿Cómo sale el paquete `ksb1_` de `klav sandbox start`? (E6.1, T172) | **(a) Nunca en `--json`: va al entorno del comando de `--` o a un archivo 0600 con `--package-file`, y la skill pide `--` (Recomendado)**<br>(b) En `--json`, como dice §4, y la skill pide usar `--`<br>(c) En `--json` solo con `--print-package`, para programas como T3 Code |
| P5 | ¿Qué comandos tiene la persona? (E6.2) | **(a) `klav proxy sandboxes` para ver todos y `klav proxy sandboxes revoke <id> \| --all` para revocar, sin Touch ID; `klav sandbox` queda para el emisor; y `klav proxy issuer add\|remove`, con Touch ID, para hacer emisor a un agente (Recomendado)**<br>(b) `klav sandbox ls\|stop` con dos modos: sin agente, la persona ve y revoca todos; con `--agent`, el emisor solo los suyos<br>(c) La persona solo lista desde la CLI; revocar, desde las apps |
| P6 | ¿Lleva la skill el sandbox? (E1.4) | **(a) Sí: `klav-forward up` instala la misma skill en `~/.claude/skills` y `~/.agents/skills` del sandbox si no hay una, y lo dice (Recomendado)**<br>(b) No: dentro del sandbox bastan el `next` de cada error y lo que el emisor le diga al agente<br>(c) Solo con `--skill`, que las líneas del *setup script* no ponen |
| Q-C | Al quitar, pausar o revocar a un emisor, ¿qué pasa con sus sandboxes vivos? (E2.2, E3.3) | **(a) Se cortan en la llamada siguiente: el servidor exige que el emisor siga en el grant del proxy y no esté en pausa (Recomendado)**<br>(b) Siguen hasta su TTL; solo se impiden los nuevos, y la hoja ofrece «Revocar los de este emisor» |
| Q-D | Un agente con `inject` (en `allow` por defecto) puede pasarle un token de proveedor al comando que crea un sandbox. ¿Qué se hace además de la skill? (T171) | **(a) `klav proxy issuer add` avisa y ofrece poner `inject` en `ask` para ese agente (Recomendado)**<br>(b) Para hacer emisor a un agente, su política tiene que tener `inject` en `ask`<br>(c) Solo se corrige el texto de T171 y del riesgo 63 |

### E10. La llave de un elemento compartida pasa al tipo `0x23` (nota del 2026-11-09)
El §2, aceptado el 2026-11-06, le dio el tipo `0x22` a la llave de un elemento compartida con HPKE. El ADR [0029](0029-anadir-dispositivo-con-qr.md), aceptado antes (2026-11-05), ya le había dado el `0x22` al paquete del enlace (*link-payload*, su §5.1 y §6). Ninguno de los dos está implementado, y la especificación (§3) sigue marcando `0x22–0x2F` como reservados. La revisión de esta enmienda lo encontró.

- **El ADR aceptado antes se queda el número.** La llave de un elemento compartida pasa al **`0x23`**, con el formato HPKE de la especificación (§8.2) y el `info` del §2, que no cambian.
- **Por qué no pueden compartirlo:** el byte de tipo nombra un solo formato (especificación §3) y va en el AAD (§8.2). Sus etiquetas de `info` ya impiden que un blob abra como el otro, pero quien lee un blob decide qué es por su tipo, y con el mismo tipo los dos formatos no se distinguen.
- **Dónde cambia:** el §2, la capa 2 del plan, las consecuencias y la casilla del roadmap. La fila del `0x23` entra en la tabla de tipos de la especificación (§3) con la capa 2, con sus vectores, como las demás.
