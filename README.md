# Palmr Demo Manager

## Description

This is a demonstration manager for Palmr, an application that creates temporary Docker container instances for demonstration purposes. The system creates containers based on the `kyantech/palmr:latest` image, monitors their status, and performs automatic cleanup after 30 minutes (1800 seconds).

The project is written in Rust, using libraries such as Axum for the web server, Bollard for Docker interaction, and Chrono for time manipulation. It ensures portability by managing cleanups internally without depending on cron jobs.

## Features

- **Demo Creation**: Creates a Docker container with persistent volume and optional Traefik configurations.
- **Rate Limiting**: Protects the `/create-demo` endpoint with a limit of 3 requests per minute per IP address.
- **Monitoring**: Checks container logs to confirm when the API and frontend are ready.
- **Status**: Endpoint to query the status of an instance (waiting, ready, timeout).
- **Automatic Cleanup**: Removes containers and volumes after the configured time.
- **Startup Recovery**: Cleans up or schedules cleanups for existing containers when starting the application.
- **Conflict Prevention**: Protects against container name conflicts, state conflicts, and ensures thread-safe operations.

## Requirements

- Rust (stable version)
- Cargo (Rust package manager)
- Docker installed and running
- Optional: Traefik for routing (set `USE_TRAEFIK=true` in environment)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/rust-generator.git
   cd rust-generator
   ```

2. Install dependencies:
   ```bash
   cargo build
   ```

## Configuration

### Environment Variables

- `USE_TRAEFIK`: Set to `true` to use Traefik for dynamic routing (default: true).
- `CLEANUP_AGE_SEC`: Defines the lifetime of instances in seconds (default: 1800).
- `BASE_DOMAIN`: Base domain for dynamic URLs (default: kyantech.com.br).
- `DOMAIN_PREFIX`: Domain prefix for dynamic URLs (default: palmr).
- Other configurations are in the code (e.g., port 3585, Docker image).

### Traefik Configuration

The system is configured to work with Traefik using the `dokploy-network`. Instances are created with:

- **Dynamic domain**: `{id}-palmr.kyantech.com.br` (where `{id}` is the instance ID)
- **Internal port**: Always 5487 (Palmr default port)
- **Access**: Only via Traefik (no external port exposure)
- **Automatic SSL**: Using the `letsencrypt` certResolver
- **HTTPS redirect**: `redirect-to-https@file` middleware

### Example of Generated Traefik Labels

```yaml
labels:
  - traefik.enable=true
  - traefik.docker.network=dokploy-network
  - traefik.http.routers.palmr-demo-{id}-web.rule=Host(`abc123-palmr.kyantech.com.br`)
  - traefik.http.routers.palmr-demo-{id}-web.entrypoints=web
  - traefik.http.routers.palmr-demo-{id}-web.service=palmr-demo-{id}-service
  - traefik.http.routers.palmr-demo-{id}-web.middlewares=redirect-to-https@file
  - traefik.http.routers.palmr-demo-{id}-websecure.rule=Host(`abc123-palmr.kyantech.com.br`)
  - traefik.http.routers.palmr-demo-{id}-websecure.entrypoints=websecure
  - traefik.http.routers.palmr-demo-{id}-websecure.service=palmr-demo-{id}-service
  - traefik.http.routers.palmr-demo-{id}-websecure.tls.certresolver=letsencrypt
  - traefik.http.services.palmr-demo-{id}-service.loadbalancer.server.port=5487
```

### DNS Configuration

For dynamic domains to work, you need to configure a wildcard DNS:

```
*.kyantech.com.br  A  <YOUR_VPS_IP>
```

This will allow any subdomain like `abc123-palmr.kyantech.com.br` to be resolved to your VPS IP, where Traefik will route to the correct container.

## Rate Limiting

The API implements rate limiting to protect against abuse:

- **Endpoint**: `/create-demo` only
- **Limit**: 3 requests per minute per IP address
- **Window**: 60-second sliding window
- **Response**: HTTP 429 (Too Many Requests) when limit exceeded
- **Other endpoints**: No rate limiting applied

### Testing Rate Limiting

Use the provided test script to verify rate limiting:

```bash
./test_rate_limit.sh
```

This script will make 4 consecutive requests to `/create-demo` and show that the 4th request returns HTTP 429.

## How to Use

1. Start the server:
   ```bash
   cargo run
   ```
   The server listens on `0.0.0.0:3585`.

2. **Create a Demo**:
   Send a POST request to `/create-demo`:
   ```bash
   curl -X POST http://localhost:3585/create-demo -H "Content-Type: application/json" -d '{"palmr_demo_instance_id": "your_instance_id"}'
   ```
   Response: JSON with confirmation message.

3. **Check Status**:
   GET to `/status/{id}`:
   ```bash
   curl http://localhost:3585/status/your_instance_id
   ```
   Possible responses:
   - {"status": "waiting", "url": null}
   - {"status": "ready", "url": "https://abc123-palmr.kyantech.com.br"} (with Traefik)
   - {"status": "timeout", "url": null}

4. **Manual Cleanup**:
   POST to `/cleanup`:
   ```bash
   curl -X POST http://localhost:3585/cleanup
   ```
   Removes old instances.

5. **Force Cleanup All**:
   POST to `/cleanup-all`:
   ```bash
   curl -X POST http://localhost:3585/cleanup-all
   ```
   Removes all demo instances (safe - won't affect the manager container).

## Docker Deployment

1. Build and run with Docker Compose:
   ```bash
   docker-compose up -d
   ```

2. Make sure the `dokploy-network` exists:
   ```bash
   docker network create dokploy-network
   ```

## How It Works Internally

- **Creation**: Connects to Docker, creates volume and container with env vars for demo mode.
- **Monitoring**: Async thread checks logs every 2 seconds until finding "API is ready!", waits 10s for frontend, updates status with URL.
- **Cleanup**: Schedules removal after the time defined in `CLEANUP_AGE_SEC` seconds, stopping/removing container and volume.
- **Recovery**: On startup, lists containers, calculates age and schedules pending cleanups.
- **Conflict Prevention**: 
  - Checks for existing containers before creation
  - Uses unique Traefik labels per instance
  - Protects the manager container from cleanup operations
  - Thread-safe state management with Mutex

## Security Features

- **Rate Limiting**: Protects against abuse with 3 requests per minute per IP on the `/create-demo` endpoint
- **Container Protection**: The manager container is never affected by cleanup operations
- **Unique Labels**: Each demo instance has unique Traefik routing labels
- **Error Handling**: Robust error handling with detailed logging
- **Resource Management**: Proper cleanup of containers, volumes, and state
- **Network Validation**: Verifies required network exists on startup

## Troubleshooting

### Certificate Authority Issues
If you get "certificate authority invalid" errors:
- Ensure DNS wildcard is properly configured
- Check Traefik logs for Let's Encrypt errors
- Verify ports 80 and 443 are accessible
- For testing, use `curl -k` to ignore certificate validation

### Container Conflicts
- The system prevents duplicate container names
- Each instance ID can only be processed once
- Cleanup operations are safe and won't affect the manager