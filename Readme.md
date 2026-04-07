# Titanium - URL to PNG Screenshot Service

A web service that captures screenshots of web pages as PNG images using headless Chromium. Simple HTTP API, runs in Docker/k8s without GPU.

## API

### Render URL to PNG
```
GET /render.png?url={base64_encoded_url}&w={width}&h={height}
```

- `url`: URL-safe base64-encoded URL
- `w`: viewport width in pixels
- `h`: viewport height in pixels

```bash
# Encode URL and capture screenshot
URL=$(echo -n "https://example.com" | base64 -w0)
curl "http://localhost:3000/render.png?url=$URL&w=800&h=600" > screenshot.png
```

### Health Check
```
GET /health
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
./target/release/titanium
```

Server starts on `http://localhost:3000`.

## Development

```bash
cargo test --all-features
cargo run
```

## Architecture

- **Rust** with Axum for the HTTP server
- **Chromium** (headless) via `chromiumoxide` for rendering
- Pages are rendered with full CSS, JavaScript, and font support
- Each request opens a new browser tab, sets viewport, navigates, screenshots, and closes the tab
- A single persistent browser instance is shared across requests

## License

MIT
