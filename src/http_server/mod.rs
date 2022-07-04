mod endpoints;
mod layer;

use crate::http_server::layer::logging::LoggingMiddleware;
use axum::{routing::get, Router};
use tower_layer::layer_fn;

#[must_use]
pub fn build_http_router() -> Router {
    Router::new()
        .route("/dl", get(endpoints::dl::get))
        .layer(layer_fn(LoggingMiddleware))
}
