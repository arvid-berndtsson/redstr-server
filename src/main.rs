use axum::{
    extract::Json,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::{info, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Request payload for /transform endpoint
#[derive(Debug, Deserialize)]
struct TransformRequest {
    function: String,
    input: String,
}

/// Response payload for /transform endpoint
#[derive(Debug, Serialize)]
struct TransformResponse {
    output: String,
}

/// Request payload for /batch endpoint
#[derive(Debug, Deserialize)]
struct BatchRequest {
    transforms: Vec<TransformRequest>,
}

/// Response payload for /batch endpoint
#[derive(Debug, Serialize)]
struct BatchResponse {
    results: Vec<TransformResponse>,
}

/// Error response
#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

/// Version response
#[derive(Debug, Serialize)]
struct VersionResponse {
    service: String,
    version: String,
    redstr_version: String,
}

/// Root response
#[derive(Debug, Serialize)]
struct RootResponse {
    service: String,
    version: String,
    endpoints: Vec<String>,
}

/// Health response
#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
}

/// Functions response
#[derive(Debug, Serialize)]
struct FunctionsResponse {
    functions: Vec<String>,
    count: usize,
}

#[tokio::main]
async fn main() {
    // Initialize tracing subscriber for structured logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=debug,axum=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting redstr HTTP server");

    // Build the application with routes
    let app = Router::new()
        .route("/", get(root_handler))
        .route("/health", get(health_handler))
        .route("/version", get(version_handler))
        .route("/functions", get(functions_handler))
        .route("/transform", post(transform_handler))
        .route("/batch", post(batch_handler))
        // Add CORS middleware
        .layer(CorsLayer::permissive())
        // Add tracing middleware for automatic request/response logging
        .layer(TraceLayer::new_for_http());

    // Bind to address (Railway sets PORT env var, default to 8080)
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let address = format!("0.0.0.0:{}", port);
    
    info!("redstr HTTP server listening on http://{}", address);
    info!("Ready to accept transformation requests");

    // Start the server
    let listener = tokio::net::TcpListener::bind(&address)
        .await
        .expect("Failed to bind to address");
    
    axum::serve(listener, app)
        .await
        .expect("Server error");
}

/// Root endpoint handler
async fn root_handler() -> Json<RootResponse> {
    Json(RootResponse {
        service: "redstr-server".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        endpoints: vec![
            "/transform".to_string(),
            "/batch".to_string(),
            "/functions".to_string(),
            "/health".to_string(),
            "/version".to_string(),
        ],
    })
}

/// Health check endpoint handler
async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
    })
}

/// Version endpoint handler
async fn version_handler() -> Json<VersionResponse> {
    Json(VersionResponse {
        service: "redstr-server".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        redstr_version: "0.2.0".to_string(), // redstr library version
    })
}

/// Functions endpoint handler
async fn functions_handler() -> Json<FunctionsResponse> {
    let functions = vec![
        // Case transformations
        "randomize_capitalization", "leetspeak", "alternate_case", "case_swap",
        "to_camel_case", "to_snake_case", "to_kebab_case",
        // Encoding
        "base64_encode", "url_encode", "hex_encode", "html_entity_encode", "mixed_encoding",
        // Injection
        "sql_comment_injection", "xss_tag_variations", "command_injection", "path_traversal",
        "null_byte_injection", "mongodb_injection", "couchdb_injection", "dynamodb_obfuscate",
        "nosql_operator_injection", "ssti_injection", "ssti_syntax_obfuscate", "ssti_framework_variation",
        // Phishing
        "domain_typosquat", "advanced_domain_spoof", "email_obfuscation", "url_shortening_pattern",
        // Obfuscation
        "rot13", "reverse_string", "vowel_swap", "double_characters", "whitespace_padding", "js_string_concat",
        // Unicode
        "homoglyph_substitution", "unicode_variations", "zalgo_text", "space_variants", "unicode_normalize_variants",
        // Cloudflare
        "cloudflare_turnstile_variation", "cloudflare_challenge_response", "tls_fingerprint_variation",
        "tls_handshake_pattern", "canvas_fingerprint_variation", "webgl_fingerprint_obfuscate",
        "font_fingerprint_consistency",
        // Web Security
        "http_header_variation", "api_endpoint_variation", "graphql_obfuscate", "graphql_variable_injection",
        "graphql_introspection_bypass", "session_token_variation", "jwt_header_manipulation",
        "jwt_payload_obfuscate", "jwt_algorithm_confusion", "jwt_signature_bypass",
        // Shell
        "bash_obfuscate", "powershell_obfuscate", "env_var_obfuscate", "file_path_obfuscate",
        // Bot detection
        "random_user_agent", "http2_header_order", "cloudflare_challenge_variation", "accept_language_variation",
    ];

    Json(FunctionsResponse {
        count: functions.len(),
        functions: functions.into_iter().map(String::from).collect(),
    })
}

/// Transform endpoint handler
async fn transform_handler(
    Json(payload): Json<TransformRequest>,
) -> Response {
    info!(function = %payload.function, "Processing transformation request");
    
    match execute_transform(&payload.function, &payload.input) {
        Ok(output) => {
            info!(function = %payload.function, "Transformation successful");
            (StatusCode::OK, Json(TransformResponse { output })).into_response()
        }
        Err(err) => {
            error!(function = %payload.function, error = %err, "Transformation failed");
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { error: err }),
            )
                .into_response()
        }
    }
}

/// Batch transform endpoint handler
async fn batch_handler(
    Json(payload): Json<BatchRequest>,
) -> Response {
    info!(count = payload.transforms.len(), "Processing batch transformation request");
    
    if payload.transforms.is_empty() {
        error!("Batch request contains no transforms");
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "No transforms provided".to_string(),
            }),
        )
            .into_response();
    }

    let mut results = Vec::new();
    for transform in payload.transforms {
        match execute_transform(&transform.function, &transform.input) {
            Ok(output) => results.push(TransformResponse { output }),
            Err(err) => {
                error!(function = %transform.function, error = %err, "Batch transformation failed");
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: format!("Transform failed: {}", err),
                    }),
                )
                    .into_response();
            }
        }
    }

    info!(count = results.len(), "Batch transformation successful");
    (StatusCode::OK, Json(BatchResponse { results })).into_response()
}

/// Execute the transformation using redstr library
fn execute_transform(function: &str, input: &str) -> Result<String, String> {
    let output = match function {
        // Case transformations
        "randomize_capitalization" => redstr::randomize_capitalization(input),
        "leetspeak" => redstr::leetspeak(input),
        "alternate_case" => redstr::alternate_case(input),
        "case_swap" => redstr::case_swap(input),
        "to_camel_case" => redstr::to_camel_case(input),
        "to_snake_case" => redstr::to_snake_case(input),
        "to_kebab_case" => redstr::to_kebab_case(input),
        
        // Encoding
        "base64_encode" => redstr::base64_encode(input),
        "url_encode" => redstr::url_encode(input),
        "hex_encode" => redstr::hex_encode(input),
        "html_entity_encode" => redstr::html_entity_encode(input),
        "mixed_encoding" => redstr::mixed_encoding(input),
        
        // Injection
        "sql_comment_injection" => redstr::sql_comment_injection(input),
        "xss_tag_variations" => redstr::xss_tag_variations(input),
        "command_injection" => redstr::command_injection(input),
        "path_traversal" => redstr::path_traversal(input),
        "null_byte_injection" => redstr::null_byte_injection(input),
        "mongodb_injection" => redstr::mongodb_injection(input),
        "couchdb_injection" => redstr::couchdb_injection(input),
        "dynamodb_obfuscate" => redstr::dynamodb_obfuscate(input),
        "nosql_operator_injection" => redstr::nosql_operator_injection(input),
        "ssti_injection" => redstr::ssti_injection(input),
        "ssti_syntax_obfuscate" => redstr::ssti_syntax_obfuscate(input),
        "ssti_framework_variation" => {
            // For this function, we expect input format: "template|framework"
            let parts: Vec<&str> = input.split('|').collect();
            if parts.len() == 2 {
                redstr::ssti_framework_variation(parts[0], parts[1])
            } else {
                // Default to jinja2 if no framework specified
                redstr::ssti_framework_variation(input, "jinja2")
            }
        },
        
        // Phishing
        "domain_typosquat" => redstr::domain_typosquat(input),
        "advanced_domain_spoof" => redstr::advanced_domain_spoof(input),
        "email_obfuscation" => redstr::email_obfuscation(input),
        "url_shortening_pattern" => redstr::url_shortening_pattern(input),
        
        // Obfuscation
        "rot13" => redstr::rot13(input),
        "reverse_string" => redstr::reverse_string(input),
        "vowel_swap" => redstr::vowel_swap(input),
        "double_characters" => redstr::double_characters(input),
        "whitespace_padding" => redstr::whitespace_padding(input),
        "js_string_concat" => redstr::js_string_concat(input),
        
        // Unicode
        "homoglyph_substitution" => redstr::homoglyph_substitution(input),
        "unicode_variations" => redstr::unicode_variations(input),
        "zalgo_text" => redstr::zalgo_text(input),
        "space_variants" => redstr::space_variants(input),
        "unicode_normalize_variants" => redstr::unicode_normalize_variants(input),
        
        // Cloudflare
        "cloudflare_turnstile_variation" => redstr::cloudflare_turnstile_variation(input),
        "cloudflare_challenge_response" => redstr::cloudflare_challenge_response(input),
        "tls_fingerprint_variation" => redstr::tls_fingerprint_variation(input),
        "tls_handshake_pattern" => redstr::tls_handshake_pattern(input),
        "canvas_fingerprint_variation" => redstr::canvas_fingerprint_variation(input),
        "webgl_fingerprint_obfuscate" => redstr::webgl_fingerprint_obfuscate(input),
        "font_fingerprint_consistency" => redstr::font_fingerprint_consistency(input),
        
        // Web Security
        "http_header_variation" => redstr::http_header_variation(input),
        "api_endpoint_variation" => redstr::api_endpoint_variation(input),
        "graphql_obfuscate" => redstr::graphql_obfuscate(input),
        "graphql_variable_injection" => redstr::graphql_variable_injection(input),
        "graphql_introspection_bypass" => redstr::graphql_introspection_bypass(input),
        "session_token_variation" => redstr::session_token_variation(input),
        "jwt_header_manipulation" => redstr::jwt_header_manipulation(input),
        "jwt_payload_obfuscate" => redstr::jwt_payload_obfuscate(input),
        "jwt_algorithm_confusion" => redstr::jwt_algorithm_confusion(input),
        "jwt_signature_bypass" => redstr::jwt_signature_bypass(input),
        
        // Shell
        "bash_obfuscate" => redstr::bash_obfuscate(input),
        "powershell_obfuscate" => redstr::powershell_obfuscate(input),
        "env_var_obfuscate" => redstr::env_var_obfuscate(input),
        "file_path_obfuscate" => redstr::file_path_obfuscate(input),
        
        // Bot detection
        "random_user_agent" => redstr::random_user_agent(), // No input needed - generates random UA
        "http2_header_order" => redstr::http2_header_order(input),
        "cloudflare_challenge_variation" => redstr::cloudflare_challenge_variation(input),
        "accept_language_variation" => redstr::accept_language_variation(input),
        
        _ => return Err(format!("Unknown function: {}", function)),
    };
    
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_transform_base64_encode() {
        let result = execute_transform("base64_encode", "test");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "dGVzdA==");
    }

    #[test]
    fn test_execute_transform_reverse_string() {
        let result = execute_transform("reverse_string", "hello");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "olleh");
    }

    #[test]
    fn test_execute_transform_unknown_function() {
        let result = execute_transform("unknown_func", "test");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown function"));
    }

    #[test]
    fn test_execute_transform_rot13() {
        let result = execute_transform("rot13", "hello");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "uryyb");
    }

    #[test]
    fn test_execute_transform_url_encode() {
        let result = execute_transform("url_encode", "hello world");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "hello%20world");
    }
}
