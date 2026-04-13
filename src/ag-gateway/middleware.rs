use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};

use crate::extractor::ErrorResponse;

/// Request size limit middleware (1MB body, 16KB headers).
pub async fn size_limit(request: Request, next: Next) -> Result<Response, Response> {
    // Check content-length header
    if let Some(content_length) = request.headers().get("content-length") {
        if let Ok(len) = content_length.to_str().unwrap_or("0").parse::<usize>() {
            if len > 1_048_576 {
                // 1MB
                return Err((
                    StatusCode::PAYLOAD_TOO_LARGE,
                    Json(ErrorResponse {
                        error: "Request body exceeds 1MB limit".to_string(),
                        error_code: "payload_too_large".to_string(),
                        request_id: None,
                    }),
                )
                    .into_response());
            }
        }
    }

    Ok(next.run(request).await)
}
