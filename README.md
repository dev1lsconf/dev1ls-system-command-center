# dev1ls System Command Center v2.0

Panel web de monitoreo de sistema con estilo terminal retro. Diseñado para servidores personales y estaciones de trabajo Arch Linux.

## Arquitectura

```
┌─────────┐     ┌──────────┐     ┌──────────┐
│ Browser │────▶│ server.py│────▶│metrics-  │
│ :8001   │     │ :8001    │     │api.py    │
│         │     │ (proxy)  │     │ :8090    │
└─────────┘     └──────────┘     └────┬─────┘
                                      │
                            ┌─────────▼─────────┐
                            │ Sistema (journal,  │
                            │  nft, fail2ban,    │
                            │  procfs, df, etc)  │
                            └───────────────────┘
```

## Puertos

| Puerto | Servicio    | Descripción                     |
|--------|-------------|---------------------------------|
| 8001   | server.py   | Web panel + proxy a la API      |
| 8090   | metrics-api | API REST de métricas del sistema |

## Componentes

### `server.py`
Sirve el frontend (`index.html`) y archivos estáticos. Proxy reversa hacia `metrics-api.py` en `/api/*`.

### `metrics-api.py`
API REST que recolecta métricas del sistema en tiempo real:

- **CPU**: modelo, núcleos, uso %, temperatura, load average
- **Memoria**: total, usada, disponible, swap
- **Disco**: uso por partición, temperatura (smartctl)
- **Red**: interfaces, direcciones IP, tráfico RX/TX, ancho de banda
- **Firewall**: estado de nftables, reglas, contadores de drops/rejects
- **Fail2ban**: jails, IPs baneadas, estadísticas de intentos
- **Servicios**: estado de procesos críticos (docker, tailscale, sshd, etc.)
- **Conexiones**: conexiones activas con GeoIP (ciudad, país, ISP, coordenadas)
- **Logs**: alertas desde journal del sistema y del kernel
- **Procesos**: top 15 procesos por uso de CPU

### `index.html`
Frontend con diseño monospace verde-sobre-negro. Incluye:

- Cards de métricas en grid responsive
- Mapa GeoIP (Leaflet + CartoDB dark tiles) con conexiones SSH marcadas en rojo
- Tabla de IPs conectadas con geolocalización
- Lista de IPs baneadas por fail2ban
- Alertas en tiempo real desde journal del sistema

### `log_tailer.py` (servicio auxiliar)
Tail de logs del sistema para mejorar la respuesta del endpoint `/api/logs`.

### `config.json`
Configuración centralizada:

```json
{
  "port": 8090,
  "web_port": 8001,
  "auth_user": "dev1ls",
  "auth_password": "",
  "rate_limit_requests": 60,
  "rate_limit_window": 60,
  "critical_services": ["docker", "tailscale", "fail2ban", "sshd", "nftables"],
  "version": "2.0"
}
```

## Endpoints API

- `GET /api/metrics` — todas las métricas del sistema
- `GET /api/logs?lines=N` — logs recientes y alertas
- `GET /api/health` — healthcheck del servicio

## Instalación

```bash
# Iniciar servidor web (puerto 8001)
python3 server.py

# Iniciar API de métricas (puerto 8090)
python3 metrics-api.py

# Opcional: tail de logs
python3 log_tailer.py
```

## Dependencias

- Python 3.8+
- `nftables` (firewall)
- `fail2ban` (opcional, para bloqueo de IPs)
- Acceso a `journalctl` (para alertas del sistema)

## Notas

- La API necesita permisos de `sudo` para consultar nftables y fail2ban
- El mapa Leaflet carga tiles desde CartoDB CDN (requiere internet)
- Las conexiones GeoIP usan ip-api.com (free tier, 45 req/min)
