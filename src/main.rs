use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use base64::{engine::general_purpose::URL_SAFE, Engine};
use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::emulation::SetDeviceMetricsOverrideParams;
use chromiumoxide::cdp::browser_protocol::page::CaptureScreenshotFormat;
use chromiumoxide::page::ScreenshotParams;
use futures::StreamExt;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::{env, io::Cursor, net::SocketAddr, path::PathBuf, sync::Arc, time::Instant};
use tokio::fs;
use tower_http::trace::TraceLayer;
use tracing::{info, Level};
use url::Url;

struct AppState {
    browser: Browser,
    signing_key: Option<String>,
}

// --- Shared param types ---

#[derive(Debug, Deserialize, PartialEq)]
struct RenderParams {
    url: String,
    w: u32,
    h: u32,
    verify: Option<String>,
    cache: Option<u64>,
    delay: Option<u64>,
}

#[derive(Debug, Deserialize, PartialEq)]
struct AnimateParams {
    url: String,
    w: u32,
    h: u32,
    duration: Option<f32>,
    fps: Option<u32>,
    verify: Option<String>,
    cache: Option<u64>,
    delay: Option<u64>,
}

// --- Signature verification ---

fn compute_signature(canonical: &str, signing_key: &str) -> Result<String, String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(signing_key.as_bytes())
        .map_err(|_| "Invalid signing key".to_string())?;
    mac.update(canonical.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn verify_render_signature(params: &RenderParams, signing_key: &str) -> Result<(), String> {
    let sig = params.verify.as_deref().ok_or("Missing verify parameter")?;
    let mut parts = vec![
        format!("h={}", params.h),
        format!("url={}", params.url),
        format!("w={}", params.w),
    ];
    if let Some(cache) = params.cache {
        parts.push(format!("cache={}", cache));
    }
    if let Some(delay) = params.delay {
        parts.push(format!("delay={}", delay));
    }
    parts.sort();
    let canonical = parts.join("&");
    let expected = compute_signature(&canonical, signing_key)?;
    if sig != expected {
        return Err("Invalid signature".to_string());
    }
    Ok(())
}

fn verify_animate_signature(params: &AnimateParams, signing_key: &str) -> Result<(), String> {
    let sig = params.verify.as_deref().ok_or("Missing verify parameter")?;
    let mut parts = vec![
        format!("h={}", params.h),
        format!("url={}", params.url),
        format!("w={}", params.w),
    ];
    if let Some(duration) = params.duration {
        parts.push(format!("duration={}", duration));
    }
    if let Some(fps) = params.fps {
        parts.push(format!("fps={}", fps));
    }
    if let Some(cache) = params.cache {
        parts.push(format!("cache={}", cache));
    }
    if let Some(delay) = params.delay {
        parts.push(format!("delay={}", delay));
    }
    parts.sort();
    let canonical = parts.join("&");
    let expected = compute_signature(&canonical, signing_key)?;
    if sig != expected {
        return Err("Invalid signature".to_string());
    }
    Ok(())
}

// --- Caching ---

fn cache_path(canonical: &str, ttl: u64, ext: &str) -> PathBuf {
    let mut mac = Hmac::<Sha256>::new_from_slice(b"cache-key").unwrap();
    mac.update(canonical.as_bytes());
    let hash = hex::encode(mac.finalize().into_bytes());
    PathBuf::from(format!("/tmp/{}-{}.{}", ttl, &hash[..16], ext))
}

async fn try_cache_read(path: &PathBuf) -> Option<Vec<u8>> {
    let metadata = fs::metadata(path).await.ok()?;
    let modified = metadata.modified().ok()?;
    let age = modified.elapsed().ok()?;

    // Extract TTL from filename: /tmp/{TTL}-{hash}.ext
    let filename = path.file_name()?.to_str()?;
    let ttl_str = filename.split('-').next()?;
    let ttl: u64 = ttl_str.parse().ok()?;

    if age.as_secs() < ttl {
        fs::read(path).await.ok()
    } else {
        let _ = fs::remove_file(path).await;
        None
    }
}

// --- URL helpers ---

fn decode_base64_url(encoded: &str) -> Result<String, String> {
    URL_SAFE
        .decode(encoded)
        .map_err(|_| "Invalid base64".to_string())
        .and_then(|bytes| String::from_utf8(bytes).map_err(|_| "Invalid URL encoding".to_string()))
}

fn validate_url(url_str: &str) -> Result<Url, String> {
    Url::parse(url_str).map_err(|_| "Invalid URL".to_string())
}

// --- Chrome helpers ---

async fn open_page(
    browser: &Browser,
    url: &Url,
    width: u32,
    height: u32,
    delay_ms: u64,
) -> Result<chromiumoxide::Page, String> {
    let page = browser
        .new_page("about:blank")
        .await
        .map_err(|e| format!("Failed to create page: {}", e))?;

    let viewport = SetDeviceMetricsOverrideParams::new(width, height, 1.0, false);
    page.execute(viewport)
        .await
        .map_err(|e| format!("Failed to set viewport: {}", e))?;

    page.goto(url.as_str())
        .await
        .map_err(|e| format!("Failed to navigate: {}", e))?;

    // Wait for document.readyState === 'complete' (fires after load event)
    wait_for_page_ready(&page).await?;

    // Extra delay for JS-heavy pages (charts, animations, etc.)
    if delay_ms > 0 {
        info!("Waiting {}ms extra delay", delay_ms);
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
    }

    Ok(page)
}

/// Poll until document.readyState is 'complete' and no in-flight requests,
/// with a timeout so we don't hang forever on slow pages.
async fn wait_for_page_ready(page: &chromiumoxide::Page) -> Result<(), String> {
    let timeout = std::time::Duration::from_secs(30);
    let poll_interval = std::time::Duration::from_millis(100);
    let start = Instant::now();

    // Phase 1: wait for document.readyState === 'complete'
    loop {
        if start.elapsed() > timeout {
            info!("Timed out waiting for readyState, proceeding anyway");
            break;
        }
        let ready: String = page
            .evaluate("document.readyState")
            .await
            .map_err(|e| format!("readyState check failed: {}", e))?
            .into_value()
            .unwrap_or_default();
        if ready == "complete" {
            break;
        }
        tokio::time::sleep(poll_interval).await;
    }

    // Phase 2: wait for network idle (no pending fetches for 500ms)
    // Uses the PerformanceObserver trick to detect outstanding requests
    let idle_js = r#"
        new Promise((resolve) => {
            let timer = null;
            const reset = () => {
                clearTimeout(timer);
                timer = setTimeout(resolve, 500);
            };
            reset();
            const observer = new PerformanceObserver((list) => {
                reset();
            });
            observer.observe({ type: 'resource', buffered: false });
            // Fallback: resolve after 5s no matter what
            setTimeout(resolve, 5000);
        })
    "#;
    let idle_timeout = std::time::Duration::from_secs(10);
    let _ = tokio::time::timeout(idle_timeout, async {
        let _: Option<bool> = page
            .evaluate(idle_js)
            .await
            .ok()
            .and_then(|v| v.into_value().ok());
    })
    .await;

    Ok(())
}

async fn capture_frame(page: &chromiumoxide::Page) -> Result<Vec<u8>, String> {
    page.screenshot(
        ScreenshotParams::builder()
            .format(CaptureScreenshotFormat::Png)
            .build(),
    )
    .await
    .map_err(|e| format!("Screenshot failed: {}", e))
}

// --- Screenshot endpoint ---

async fn render_screenshot(
    browser: &Browser,
    url: &Url,
    width: u32,
    height: u32,
    delay_ms: u64,
) -> Result<Vec<u8>, String> {
    let page = open_page(browser, url, width, height, delay_ms).await?;
    let png_data = capture_frame(&page).await?;
    let _ = page.close().await;
    Ok(png_data)
}

async fn render_url(
    State(state): State<Arc<AppState>>,
    Query(params): Query<RenderParams>,
) -> impl IntoResponse {
    let start = Instant::now();

    if let Some(ref key) = state.signing_key {
        if let Err(e) = verify_render_signature(&params, key) {
            return (StatusCode::UNAUTHORIZED, e).into_response();
        }
    }

    let decoded = match decode_base64_url(&params.url) {
        Ok(d) => d,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let url = match validate_url(&decoded) {
        Ok(u) => u,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    // Check cache
    let cache_file = params.cache.map(|ttl| {
        let canonical = format!("h={}&url={}&w={}", params.h, params.url, params.w);
        cache_path(&canonical, ttl, "png")
    });
    if let Some(ref path) = cache_file {
        if let Some(data) = try_cache_read(path).await {
            info!("Cache hit for URL: {}", url);
            let cache_header = format!("public, max-age={}", params.cache.unwrap_or(0));
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "image/png")
                .header(header::CACHE_CONTROL, cache_header)
                .body(axum::body::Body::from(data))
                .unwrap()
                .into_response();
        }
    }

    info!(
        "Starting render for URL: {} ({}x{})",
        url, params.w, params.h
    );

    let delay_ms = params.delay.unwrap_or(0).min(30000);

    match render_screenshot(&state.browser, &url, params.w, params.h, delay_ms).await {
        Ok(png_data) => {
            let total_time = start.elapsed();
            info!(
                "Render completed - {} bytes, took {:?}",
                png_data.len(),
                total_time
            );

            // Write cache
            if let Some(ref path) = cache_file {
                let _ = fs::write(path, &png_data).await;
            }

            let cache_header = match params.cache {
                Some(ttl) => format!("public, max-age={}", ttl),
                None => "no-store".to_string(),
            };

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "image/png")
                .header(header::CACHE_CONTROL, cache_header)
                .body(axum::body::Body::from(png_data))
                .unwrap()
                .into_response()
        }
        Err(error) => {
            info!("Render failed: {}", error);
            (StatusCode::INTERNAL_SERVER_ERROR, error).into_response()
        }
    }
}

// --- Animation endpoint ---

fn decode_png_to_rgba(png_bytes: &[u8]) -> Result<(u32, u32, Vec<u8>), String> {
    let decoder = png::Decoder::new(Cursor::new(png_bytes));
    let mut reader = decoder
        .read_info()
        .map_err(|e| format!("PNG decode error: {}", e))?;
    let mut buf = vec![0u8; reader.output_buffer_size()];
    let info = reader
        .next_frame(&mut buf)
        .map_err(|e| format!("PNG frame error: {}", e))?;

    let width = info.width;
    let height = info.height;

    // Convert to RGBA if needed
    let rgba = match info.color_type {
        png::ColorType::Rgba => buf[..info.buffer_size()].to_vec(),
        png::ColorType::Rgb => {
            let rgb = &buf[..info.buffer_size()];
            let mut rgba = Vec::with_capacity((width * height * 4) as usize);
            for pixel in rgb.chunks(3) {
                rgba.extend_from_slice(pixel);
                rgba.push(255);
            }
            rgba
        }
        other => return Err(format!("Unsupported color type: {:?}", other)),
    };

    Ok((width, height, rgba))
}

fn encode_apng(frames: &[(u32, u32, Vec<u8>)], fps: u32) -> Result<Vec<u8>, String> {
    if frames.is_empty() {
        return Err("No frames to encode".to_string());
    }

    let (width, height, _) = &frames[0];
    let mut output = Vec::new();

    {
        let mut encoder = png::Encoder::new(&mut output, *width, *height);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        encoder
            .set_animated(frames.len() as u32, 0)
            .map_err(|e| format!("APNG setup error: {}", e))?;

        let mut writer = encoder
            .write_header()
            .map_err(|e| format!("APNG header error: {}", e))?;

        for (_, _, rgba) in frames {
            writer
                .set_frame_delay(1, fps as u16)
                .map_err(|e| format!("Frame delay error: {}", e))?;
            writer
                .write_image_data(rgba)
                .map_err(|e| format!("Frame write error: {}", e))?;
        }
    }

    Ok(output)
}

async fn render_animation(
    browser: &Browser,
    url: &Url,
    width: u32,
    height: u32,
    duration: f32,
    fps: u32,
    delay_ms: u64,
) -> Result<Vec<u8>, String> {
    let page = open_page(browser, url, width, height, delay_ms).await?;

    let total_frames = (duration * fps as f32).ceil() as u32;
    let frame_interval = std::time::Duration::from_millis((1000 / fps) as u64);

    info!(
        "Capturing {} frames at {} fps over {}s",
        total_frames, fps, duration
    );

    let mut frames = Vec::with_capacity(total_frames as usize);
    for i in 0..total_frames {
        let frame_start = Instant::now();
        let png_bytes = capture_frame(&page).await?;
        let (w, h, rgba) = decode_png_to_rgba(&png_bytes)?;
        frames.push((w, h, rgba));

        if i < total_frames - 1 {
            let elapsed = frame_start.elapsed();
            if elapsed < frame_interval {
                tokio::time::sleep(frame_interval - elapsed).await;
            }
        }
    }

    let _ = page.close().await;

    encode_apng(&frames, fps)
}

async fn animate_url(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AnimateParams>,
) -> impl IntoResponse {
    let start = Instant::now();

    if let Some(ref key) = state.signing_key {
        if let Err(e) = verify_animate_signature(&params, key) {
            return (StatusCode::UNAUTHORIZED, e).into_response();
        }
    }

    let decoded = match decode_base64_url(&params.url) {
        Ok(d) => d,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let url = match validate_url(&decoded) {
        Ok(u) => u,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let duration = params.duration.unwrap_or(3.0).clamp(0.1, 10.0);
    let fps = params.fps.unwrap_or(10).clamp(1, 30);

    // Check cache
    let cache_file = params.cache.map(|ttl| {
        let canonical = format!(
            "duration={}&fps={}&h={}&url={}&w={}",
            duration, fps, params.h, params.url, params.w
        );
        cache_path(&canonical, ttl, "apng")
    });
    if let Some(ref path) = cache_file {
        if let Some(data) = try_cache_read(path).await {
            info!("Cache hit for animation: {}", url);
            let cache_header = format!("public, max-age={}", params.cache.unwrap_or(0));
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "image/apng")
                .header(header::CACHE_CONTROL, cache_header)
                .body(axum::body::Body::from(data))
                .unwrap()
                .into_response();
        }
    }

    info!(
        "Starting animation for URL: {} ({}x{}, {}s @ {}fps)",
        url, params.w, params.h, duration, fps
    );

    let delay_ms = params.delay.unwrap_or(0).min(30000);

    match render_animation(&state.browser, &url, params.w, params.h, duration, fps, delay_ms).await
    {
        Ok(apng_data) => {
            let total_time = start.elapsed();
            info!(
                "Animation completed - {} bytes, took {:?}",
                apng_data.len(),
                total_time
            );

            if let Some(ref path) = cache_file {
                let _ = fs::write(path, &apng_data).await;
            }

            let cache_header = match params.cache {
                Some(ttl) => format!("public, max-age={}", ttl),
                None => "no-store".to_string(),
            };

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "image/apng")
                .header(header::CACHE_CONTROL, cache_header)
                .body(axum::body::Body::from(apng_data))
                .unwrap()
                .into_response()
        }
        Err(error) => {
            info!("Animation failed: {}", error);
            (StatusCode::INTERNAL_SERVER_ERROR, error).into_response()
        }
    }
}

// --- Health check ---

async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

// --- Main ---

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .with_max_level(Level::INFO)
        .init();

    info!("Launching headless Chrome...");
    let (browser, mut handler) = Browser::launch(
        BrowserConfig::builder()
            .no_sandbox()
            .arg("--disable-gpu")
            .arg("--disable-dev-shm-usage")
            .build()
            .expect("Failed to build browser config"),
    )
    .await
    .expect("Failed to launch Chrome");

    tokio::spawn(async move {
        while let Some(h) = handler.next().await {
            if h.is_err() {
                break;
            }
        }
    });

    let signing_key = env::var("SIGNING_KEY").ok();
    if signing_key.is_some() {
        info!("Request signature verification enabled");
    } else {
        info!("No SIGNING_KEY set - requests are unauthenticated");
    }

    let state = Arc::new(AppState {
        browser,
        signing_key,
    });
    info!("Chrome launched successfully");

    let app = Router::new()
        .route("/render.png", get(render_url))
        .route("/render.apng", get(animate_url))
        .route("/health", get(health_check))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    info!("Starting server on port 3000");

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_base64_url_valid() {
        let encoded = "aHR0cHM6Ly9nb29nbGUuY29t";
        let result = decode_base64_url(encoded);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://google.com");
    }

    #[test]
    fn test_decode_base64_url_invalid() {
        let encoded = "invalid@@base64";
        let result = decode_base64_url(encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_url_valid() {
        let url = "https://google.com";
        let result = validate_url(url);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_url_invalid() {
        let url = "not a url";
        let result = validate_url(url);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_health_check() {
        let response = health_check().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_verify_render_signature_valid() {
        let key = "test-secret";
        let canonical = "h=600&url=aHR0cHM6Ly9leGFtcGxlLmNvbQ==&w=800";
        let sig = compute_signature(canonical, key).unwrap();

        let params = RenderParams {
            url: "aHR0cHM6Ly9leGFtcGxlLmNvbQ==".to_string(),
            w: 800,
            h: 600,
            verify: Some(sig),
            cache: None,
            delay: None,
        };
        assert!(verify_render_signature(&params, key).is_ok());
    }

    #[test]
    fn test_verify_render_signature_invalid() {
        let params = RenderParams {
            url: "aHR0cHM6Ly9leGFtcGxlLmNvbQ==".to_string(),
            w: 800,
            h: 600,
            verify: Some("bad-signature".to_string()),
            cache: None,
            delay: None,
        };
        assert!(verify_render_signature(&params, "test-secret").is_err());
    }

    #[test]
    fn test_verify_render_signature_missing() {
        let params = RenderParams {
            url: "aHR0cHM6Ly9leGFtcGxlLmNvbQ==".to_string(),
            w: 800,
            h: 600,
            verify: None,
            cache: None,
            delay: None,
        };
        assert!(verify_render_signature(&params, "test-secret").is_err());
    }

    #[test]
    fn test_encode_apng_empty() {
        assert!(encode_apng(&[], 10).is_err());
    }

    #[test]
    fn test_encode_apng_single_frame() {
        // 2x2 red RGBA image
        let rgba = vec![
            255, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, 255, 255, 0, 255,
        ];
        let frames = vec![(2, 2, rgba)];
        let result = encode_apng(&frames, 10);
        assert!(result.is_ok());
        let data = result.unwrap();
        // Should start with PNG magic bytes
        assert_eq!(&data[..4], &[137, 80, 78, 71]);
    }

    #[test]
    fn test_cache_path_deterministic() {
        let p1 = cache_path("h=600&url=abc&w=800", 300, "png");
        let p2 = cache_path("h=600&url=abc&w=800", 300, "png");
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_cache_path_varies_with_params() {
        let p1 = cache_path("h=600&url=abc&w=800", 300, "png");
        let p2 = cache_path("h=600&url=xyz&w=800", 300, "png");
        assert_ne!(p1, p2);
    }
}
