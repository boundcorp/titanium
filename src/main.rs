use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use base64::{engine::general_purpose::URL_SAFE, Engine};
use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::page::ScreenshotParams;
use chromiumoxide::cdp::browser_protocol::emulation::SetDeviceMetricsOverrideParams;
use chromiumoxide::cdp::browser_protocol::page::CaptureScreenshotFormat;
use futures::StreamExt;
use serde::Deserialize;
use std::{net::SocketAddr, sync::Arc, time::Instant};
use tower_http::trace::TraceLayer;
use tracing::{info, Level};
use url::Url;

#[derive(Debug, Deserialize, PartialEq)]
struct RenderParams {
    url: String,
    w: u32,
    h: u32,
}

fn decode_base64_url(encoded: &str) -> Result<String, String> {
    URL_SAFE
        .decode(encoded)
        .map_err(|_| "Invalid base64".to_string())
        .and_then(|bytes| String::from_utf8(bytes).map_err(|_| "Invalid URL encoding".to_string()))
}

fn validate_url(url_str: &str) -> Result<Url, String> {
    Url::parse(url_str).map_err(|_| "Invalid URL".to_string())
}

async fn render_screenshot(browser: &Browser, url: &Url, width: u32, height: u32) -> Result<Vec<u8>, String> {
    let page = browser
        .new_page("about:blank")
        .await
        .map_err(|e| format!("Failed to create page: {}", e))?;

    // Set viewport dimensions
    let viewport = SetDeviceMetricsOverrideParams::new(width, height, 1.0, false);
    page.execute(viewport)
        .await
        .map_err(|e| format!("Failed to set viewport: {}", e))?;

    // Navigate and wait for page load
    page.goto(url.as_str())
        .await
        .map_err(|e| format!("Failed to navigate: {}", e))?;

    // Take screenshot
    let png_data = page
        .screenshot(
            ScreenshotParams::builder()
                .format(CaptureScreenshotFormat::Png)
                .build(),
        )
        .await
        .map_err(|e| format!("Screenshot failed: {}", e))?;

    // Close the page
    let _ = page.close().await;

    Ok(png_data)
}

async fn render_url(
    State(browser): State<Arc<Browser>>,
    Query(params): Query<RenderParams>,
) -> impl IntoResponse {
    let start = Instant::now();

    let decoded = match decode_base64_url(&params.url) {
        Ok(d) => d,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    let url = match validate_url(&decoded) {
        Ok(u) => u,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };

    info!("Starting render for URL: {} ({}x{})", url, params.w, params.h);

    match render_screenshot(&browser, &url, params.w, params.h).await {
        Ok(png_data) => {
            let total_time = start.elapsed();
            info!(
                "Render completed - {} bytes, took {:?}",
                png_data.len(),
                total_time
            );
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "image/png")
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

async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

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

    // Spawn the browser event handler
    tokio::spawn(async move {
        while let Some(h) = handler.next().await {
            if h.is_err() {
                break;
            }
        }
    });

    let browser = Arc::new(browser);
    info!("Chrome launched successfully");

    let app = Router::new()
        .route("/render.png", get(render_url))
        .route("/health", get(health_check))
        .layer(TraceLayer::new_for_http())
        .with_state(browser);

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
}
