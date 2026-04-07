# Titanium - URL Screenshot & Animation Service

A web service that captures screenshots and animated recordings of web pages using headless Chromium. Simple HTTP API, runs in Docker/k8s without GPU.

## API

### Render URL to PNG
```
GET /render.png?url={base64_url}&w={width}&h={height}[&cache={ttl}][&verify={sig}]
```

### Render URL to Animated PNG (APNG)
```
GET /render.apng?url={base64_url}&w={width}&h={height}[&duration={secs}][&fps={fps}][&cache={ttl}][&verify={sig}]
```

### Parameters

| Param | Required | Default | Description |
|-------|----------|---------|-------------|
| `url` | yes | - | URL-safe base64-encoded URL |
| `w` | yes | - | Viewport width in pixels |
| `h` | yes | - | Viewport height in pixels |
| `duration` | no | 3 | Animation duration in seconds (max 10, APNG only) |
| `fps` | no | 10 | Frames per second (max 30, APNG only) |
| `cache` | no | - | Cache TTL in seconds. Serves cached result if available |
| `verify` | no | - | HMAC-SHA256 signature (required when `SIGNING_KEY` is set) |

### Health Check
```
GET /health
```

## Examples

```bash
# Screenshot of example.com
URL=$(echo -n "https://example.com" | base64 -w0)
curl "http://localhost:3000/render.png?url=$URL&w=800&h=600" > screenshot.png

# Animated capture of a page (3 seconds, 10 fps)
curl "http://localhost:3000/render.apng?url=$URL&w=800&h=600&duration=3&fps=10" > animation.apng

# With caching (5 minute TTL)
curl "http://localhost:3000/render.png?url=$URL&w=800&h=600&cache=300" > cached.png
```

## Request Signing

Set `SIGNING_KEY` to require HMAC-SHA256 signatures on all render requests.

The signature is computed over the canonical query string: all params except `verify`, sorted alphabetically, joined with `&`.

```bash
# Generate signature
CANONICAL="h=600&url=${URL}&w=800"
SIG=$(echo -n "$CANONICAL" | openssl dgst -sha256 -hmac "your-secret" | cut -d' ' -f2)

curl "http://localhost:3000/render.png?url=$URL&w=800&h=600&verify=$SIG"
```

## Running

### Docker (recommended)

```bash
docker-compose up -d
```

### Local

Requires Chromium/Chrome installed on the host.

```bash
cargo build --release
SIGNING_KEY=optional-secret ./target/release/titanium
```

Server starts on `http://localhost:3000`.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SIGNING_KEY` | HMAC-SHA256 key for request verification. Omit to disable signing. |
| `RUST_LOG` | Log level (e.g. `titanium=info`) |

## Architecture

- **Rust** with Axum for the HTTP server
- **Chromium** (headless) via `chromiumoxide` for rendering
- Full CSS, JavaScript, and font support
- Single persistent browser instance, one tab per request
- APNG animation captures multiple frames with configurable timing
- File-based caching with TTL expiry in `/tmp/`

## License

MIT
