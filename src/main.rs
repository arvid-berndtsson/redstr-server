use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

/// Simple HTTP server for redstr transformations
/// Provides REST API for external tools to use redstr
///
/// Logging format:
/// All logs include structured key-value pairs for easy filtering in Railway and other platforms:
/// - level: info, warn, error
/// - type: request, success, error, response
/// - method: HTTP method (GET, POST, etc.)
/// - path: Request path
/// - client: Client IP address
/// - status: HTTP status code (for responses)
/// - message: Success message (for success logs)
/// - error: Error message (for error logs)
///
/// Example Railway filters:
/// - `level=error` - Show only errors
/// - `level=warn OR level=error` - Show warnings and errors
/// - `path=/transform` - Show logs for /transform endpoint
/// - `status=500` - Show 500 errors
/// - `"Unknown function"` - Search for specific error messages
fn main() {
    let address = "127.0.0.1:8080";
    let listener = TcpListener::bind(address)
        .expect("Failed to bind to address");
    
    println!("redstr HTTP server listening on http://{}", address);
    println!("Ready to accept transformation requests");
    
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(|| handle_client(stream));
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
            }
        }
    }
}

fn handle_client(mut stream: TcpStream) {
    // Get client address for logging
    let client_addr = stream.peer_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    
    // 8KB buffer for request handling - supports most use cases
    // For larger requests, consider using a production HTTP server library
    let mut buffer = [0; 8192];
    
    match stream.read(&mut buffer) {
        Ok(size) => {
            let request = String::from_utf8_lossy(&buffer[..size]);
            
            // Extract method and path for logging
            let (method, path) = extract_method_and_path(&request);
            log_request(&client_addr, &method, &path);
            
            // Parse HTTP request
            if request.starts_with("POST /transform") {
                handle_transform(&mut stream, &request, &client_addr);
            } else if request.starts_with("POST /batch") {
                handle_batch(&mut stream, &request, &client_addr);
            } else if request.starts_with("GET /health") {
                log_response(&client_addr, "GET", "/health", 200);
                send_response(&mut stream, 200, "OK", "application/json", r#"{"status":"healthy"}"#);
            } else if request.starts_with("GET /functions") {
                handle_functions(&mut stream, &client_addr);
            } else if request.starts_with("GET /version") {
                log_response(&client_addr, "GET", "/version", 200);
                send_response(&mut stream, 200, "OK", "application/json", r#"{"service":"redstr-server","version":"0.1.0","redstr_version":"0.2.0"}"#);
            } else if request.starts_with("GET /") {
                log_response(&client_addr, "GET", "/", 200);
                send_response(&mut stream, 200, "OK", "application/json", r#"{"service":"redstr","version":"0.2.0","endpoints":["/transform","/batch","/functions","/health","/version"]}"#);
            } else {
                log_error(&client_addr, &method, &path, "Endpoint not found");
                log_response(&client_addr, &method, &path, 404);
                send_response(&mut stream, 404, "Not Found", "text/plain", "Endpoint not found");
            }
        }
        Err(e) => {
            log_error(&client_addr, "UNKNOWN", "UNKNOWN", &format!("Failed to read from stream: {}", e));
        }
    }
}

fn handle_transform(stream: &mut TcpStream, request: &str, client_addr: &str) {
    // Extract JSON body from POST request
    let body_start = request.find("\r\n\r\n").map(|i| i + 4);
    
    if let Some(start) = body_start {
        let body = &request[start..];
        
        // Simple JSON parsing - suitable for basic use cases
        // Limitations: Does not handle nested objects, arrays, or complex escaping
        // For production use with complex JSON, consider adding serde_json dependency
        // Expected format: {"function":"method_name","input":"text"}
        let result = parse_and_transform(body);
        
        match result {
            Ok(output) => {
                log_success(client_addr, "POST", "/transform", &format!("Transformation successful"));
                log_response(client_addr, "POST", "/transform", 200);
                let response_body = format!(r#"{{"output":"{}"}}"#, escape_json(&output));
                send_response(stream, 200, "OK", "application/json", &response_body);
            }
            Err(e) => {
                log_error(client_addr, "POST", "/transform", &format!("Transformation failed: {}", e));
                log_response(client_addr, "POST", "/transform", 400);
                let error_body = format!(r#"{{"error":"{}"}}"#, escape_json(&e));
                send_response(stream, 400, "Bad Request", "application/json", &error_body);
            }
        }
    } else {
        log_error(client_addr, "POST", "/transform", "No body found in request");
        log_response(client_addr, "POST", "/transform", 400);
        send_response(stream, 400, "Bad Request", "text/plain", "No body found");
    }
}

fn parse_and_transform(json: &str) -> Result<String, String> {
    // Simple JSON parsing - extract function and input
    let function = extract_json_field(json, "function")
        .ok_or("Missing 'function' field")?;
    let input = extract_json_field(json, "input")
        .ok_or("Missing 'input' field")?;
    
    // Call appropriate redstr function
    let output = match function.as_str() {
        // Case transformations
        "randomize_capitalization" => redstr::randomize_capitalization(&input),
        "leetspeak" => redstr::leetspeak(&input),
        "alternate_case" => redstr::alternate_case(&input),
        "case_swap" => redstr::case_swap(&input),
        "to_camel_case" => redstr::to_camel_case(&input),
        "to_snake_case" => redstr::to_snake_case(&input),
        "to_kebab_case" => redstr::to_kebab_case(&input),
        
        // Encoding
        "base64_encode" => redstr::base64_encode(&input),
        "url_encode" => redstr::url_encode(&input),
        "hex_encode" => redstr::hex_encode(&input),
        "html_entity_encode" => redstr::html_entity_encode(&input),
        "mixed_encoding" => redstr::mixed_encoding(&input),
        
        // Injection
        "sql_comment_injection" => redstr::sql_comment_injection(&input),
        "xss_tag_variations" => redstr::xss_tag_variations(&input),
        "command_injection" => redstr::command_injection(&input),
        "path_traversal" => redstr::path_traversal(&input),
        "null_byte_injection" => redstr::null_byte_injection(&input),
        "mongodb_injection" => redstr::mongodb_injection(&input),
        "couchdb_injection" => redstr::couchdb_injection(&input),
        "dynamodb_obfuscate" => redstr::dynamodb_obfuscate(&input),
        "nosql_operator_injection" => redstr::nosql_operator_injection(&input),
        "ssti_injection" => redstr::ssti_injection(&input),
        "ssti_syntax_obfuscate" => redstr::ssti_syntax_obfuscate(&input),
        "ssti_framework_variation" => {
            // For this function, we expect input format: "template|framework"
            let parts: Vec<&str> = input.split('|').collect();
            if parts.len() == 2 {
                redstr::ssti_framework_variation(parts[0], parts[1])
            } else {
                // Default to jinja2 if no framework specified
                redstr::ssti_framework_variation(&input, "jinja2")
            }
        },
        
        // Phishing
        "domain_typosquat" => redstr::domain_typosquat(&input),
        "advanced_domain_spoof" => redstr::advanced_domain_spoof(&input),
        "email_obfuscation" => redstr::email_obfuscation(&input),
        "url_shortening_pattern" => redstr::url_shortening_pattern(&input),
        
        // Obfuscation
        "rot13" => redstr::rot13(&input),
        "reverse_string" => redstr::reverse_string(&input),
        "vowel_swap" => redstr::vowel_swap(&input),
        "double_characters" => redstr::double_characters(&input),
        "whitespace_padding" => redstr::whitespace_padding(&input),
        "js_string_concat" => redstr::js_string_concat(&input),
        
        // Unicode
        "homoglyph_substitution" => redstr::homoglyph_substitution(&input),
        "unicode_variations" => redstr::unicode_variations(&input),
        "zalgo_text" => redstr::zalgo_text(&input),
        "space_variants" => redstr::space_variants(&input),
        "unicode_normalize_variants" => redstr::unicode_normalize_variants(&input),
        
        // Cloudflare
        "cloudflare_turnstile_variation" => redstr::cloudflare_turnstile_variation(&input),
        "cloudflare_challenge_response" => redstr::cloudflare_challenge_response(&input),
        "tls_fingerprint_variation" => redstr::tls_fingerprint_variation(&input),
        "tls_handshake_pattern" => redstr::tls_handshake_pattern(&input),
        "canvas_fingerprint_variation" => redstr::canvas_fingerprint_variation(&input),
        "webgl_fingerprint_obfuscate" => redstr::webgl_fingerprint_obfuscate(&input),
        "font_fingerprint_consistency" => redstr::font_fingerprint_consistency(&input),
        
        // Web Security
        "http_header_variation" => redstr::http_header_variation(&input),
        "api_endpoint_variation" => redstr::api_endpoint_variation(&input),
        "graphql_obfuscate" => redstr::graphql_obfuscate(&input),
        "graphql_variable_injection" => redstr::graphql_variable_injection(&input),
        "graphql_introspection_bypass" => redstr::graphql_introspection_bypass(&input),
        "session_token_variation" => redstr::session_token_variation(&input),
        "jwt_header_manipulation" => redstr::jwt_header_manipulation(&input),
        "jwt_payload_obfuscate" => redstr::jwt_payload_obfuscate(&input),
        "jwt_algorithm_confusion" => redstr::jwt_algorithm_confusion(&input),
        "jwt_signature_bypass" => redstr::jwt_signature_bypass(&input),
        
        // Shell
        "bash_obfuscate" => redstr::bash_obfuscate(&input),
        "powershell_obfuscate" => redstr::powershell_obfuscate(&input),
        "env_var_obfuscate" => redstr::env_var_obfuscate(&input),
        "file_path_obfuscate" => redstr::file_path_obfuscate(&input),
        
        // Bot detection
        "random_user_agent" => redstr::random_user_agent(), // No input needed - generates random UA
        "http2_header_order" => redstr::http2_header_order(&input),
        "cloudflare_challenge_variation" => redstr::cloudflare_challenge_variation(&input),
        "accept_language_variation" => redstr::accept_language_variation(&input),
        
        _ => return Err(format!("Unknown function: {}", function)),
    };
    
    Ok(output)
}

fn extract_json_field(json: &str, field: &str) -> Option<String> {
    // Simple JSON field extraction - handles basic escaped quotes and backslashes
    // Limitations: Does not handle nested objects or complex JSON structures
    let pattern = format!("\"{}\":\"", field);
    let start = json.find(&pattern)? + pattern.len();
    let remaining = &json[start..];
    
    // Find the closing quote, accounting for escaped quotes
    let mut end = 0;
    let mut escaped = false;
    let mut found_closing_quote = false;
    for (i, c) in remaining.chars().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        if c == '"' {
            end = i;
            found_closing_quote = true;
            break;
        }
    }
    
    // Return None only if we didn't find a closing quote at all
    if !found_closing_quote {
        return None;
    }
    
    Some(remaining[..end].replace("\\\"", "\"").replace("\\\\", "\\")
        .replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t"))
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn handle_functions(stream: &mut TcpStream, client_addr: &str) {
    // List all available transformation functions
    // Note: This list must be kept in sync with parse_and_transform function
    // Consider using a macro or shared constant in future to avoid duplication
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
    
    let functions_json: Vec<String> = functions.iter().map(|f| format!("\"{}\"", f)).collect();
    let response_body = format!(r#"{{"functions":[{}],"count":{}}}"#, functions_json.join(","), functions.len());
    log_response(client_addr, "GET", "/functions", 200);
    send_response(stream, 200, "OK", "application/json", &response_body);
}

fn handle_batch(stream: &mut TcpStream, request: &str, client_addr: &str) {
    // Extract JSON body from POST request
    let body_start = request.find("\r\n\r\n").map(|i| i + 4);
    
    if let Some(start) = body_start {
        let body = &request[start..];
        
        // Expected format: {"transforms":[{"function":"method_name","input":"text"},{"function":"method_name2","input":"text2"}]}
        // For simplicity, we'll process each transform sequentially
        let result = parse_and_batch_transform(body);
        
        match result {
            Ok(outputs) => {
                log_success(client_addr, "POST", "/batch", &format!("Batch transformation successful: {} operations", outputs.len()));
                log_response(client_addr, "POST", "/batch", 200);
                // Escape each output and build the JSON array
                let outputs_json: Vec<String> = outputs.iter()
                    .map(|output| format!(r#"{{"output":"{}"}}"#, escape_json(output)))
                    .collect();
                let response_body = format!(r#"{{"results":[{}]}}"#, outputs_json.join(","));
                send_response(stream, 200, "OK", "application/json", &response_body);
            }
            Err(e) => {
                log_error(client_addr, "POST", "/batch", &format!("Batch transformation failed: {}", e));
                log_response(client_addr, "POST", "/batch", 400);
                let error_body = format!(r#"{{"error":"{}"}}"#, escape_json(&e));
                send_response(stream, 400, "Bad Request", "application/json", &error_body);
            }
        }
    } else {
        log_error(client_addr, "POST", "/batch", "No body found in request");
        log_response(client_addr, "POST", "/batch", 400);
        send_response(stream, 400, "Bad Request", "text/plain", "No body found");
    }
}

fn parse_and_batch_transform(json: &str) -> Result<Vec<String>, String> {
    // Simple batch processing - extract transforms array
    // Expected format: {"transforms":[{"function":"func1","input":"text1"},{"function":"func2","input":"text2"}]}
    
    // Find the transforms field (allowing for whitespace)
    let transforms_pattern = r#""transforms""#;
    let transforms_start = json.find(transforms_pattern)
        .ok_or("Missing 'transforms' field")?;
    
    // Find the opening bracket of the array (skipping whitespace and colon)
    let search_start = transforms_start + transforms_pattern.len();
    let remaining = &json[search_start..];
    let array_start_offset = remaining.chars()
        .position(|c| c == '[')
        .ok_or("Invalid transforms array format")?;
    let array_start = search_start + array_start_offset + 1;
    
    // Find matching closing bracket
    let array_end = json[array_start..].find(']')
        .map(|i| array_start + i)
        .ok_or("Invalid transforms array format")?;
    
    let transforms_json = &json[array_start..array_end];
    
    // Split by objects (simple approach - tracks braces and strings)
    // Note: This parser has limitations with complex nested structures
    // For production use, consider using serde_json for proper JSON parsing
    let mut results = Vec::new();
    let mut current_start = 0;
    let mut brace_count = 0;
    let mut in_string = false;
    let mut escaped = false;
    
    for (i, c) in transforms_json.chars().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        
        if c == '\\' {
            escaped = true;
            continue;
        }
        
        if c == '"' {
            in_string = !in_string;
            continue;
        }
        
        if in_string {
            continue;
        }
        
        if c == '{' {
            if brace_count == 0 {
                current_start = i;
            }
            brace_count += 1;
        } else if c == '}' {
            brace_count -= 1;
            if brace_count == 0 {
                // Extract and process this transform
                let transform_json = &transforms_json[current_start..=i];
                match parse_and_transform(transform_json) {
                    Ok(output) => results.push(output),
                    Err(e) => return Err(format!("Transform failed: {}", e)),
                }
            }
        }
    }
    
    if results.is_empty() {
        return Err("No valid transforms found in array".to_string());
    }
    
    Ok(results)
}

/// Get timestamp in milliseconds since UNIX epoch for logging
fn get_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Extract HTTP method and path from request string
fn extract_method_and_path(request: &str) -> (String, String) {
    let first_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    
    let method = parts.get(0).unwrap_or(&"UNKNOWN").to_string();
    let path = parts.get(1).unwrap_or(&"UNKNOWN").to_string();
    
    (method, path)
}

/// Log incoming HTTP request
fn log_request(client_addr: &str, method: &str, path: &str) {
    let timestamp = get_timestamp();
    println!("[{}] level=info type=request method={} path={} client={}", 
             timestamp, method, path, client_addr);
}

/// Log successful operation
fn log_success(client_addr: &str, method: &str, path: &str, message: &str) {
    let timestamp = get_timestamp();
    println!("[{}] level=info type=success method={} path={} client={} message=\"{}\"", 
             timestamp, method, path, client_addr, message);
}

/// Log error condition
fn log_error(client_addr: &str, method: &str, path: &str, error: &str) {
    let timestamp = get_timestamp();
    eprintln!("[{}] level=error type=error method={} path={} client={} error=\"{}\"", 
              timestamp, method, path, client_addr, error);
}

/// Log HTTP response
fn log_response(client_addr: &str, method: &str, path: &str, status: u16) {
    let timestamp = get_timestamp();
    let level = if status >= 400 { "warn" } else { "info" };
    println!("[{}] level={} type=response method={} path={} client={} status={}", 
             timestamp, level, method, path, client_addr, status);
}

fn send_response(stream: &mut TcpStream, status: u16, status_text: &str, content_type: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\n\r\n{}",
        status, status_text, content_type, body.len(), body
    );
    
    if let Err(e) = stream.write_all(response.as_bytes()) {
        eprintln!("Failed to send response: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_json_field_basic() {
        let json = r#"{"function":"leetspeak","input":"hello"}"#;
        assert_eq!(extract_json_field(json, "function"), Some("leetspeak".to_string()));
        assert_eq!(extract_json_field(json, "input"), Some("hello".to_string()));
    }

    #[test]
    fn test_extract_json_field_with_escaped_quotes() {
        let json = r#"{"function":"test","input":"hello \"world\""}"#;
        assert_eq!(extract_json_field(json, "input"), Some("hello \"world\"".to_string()));
    }

    #[test]
    fn test_extract_json_field_with_special_chars() {
        let json = r#"{"function":"test","input":"line1\nline2\ttab"}"#;
        let result = extract_json_field(json, "input");
        assert_eq!(result, Some("line1\nline2\ttab".to_string()));
    }

    #[test]
    fn test_extract_json_field_missing() {
        let json = r#"{"function":"test"}"#;
        assert_eq!(extract_json_field(json, "input"), None);
    }

    #[test]
    fn test_escape_json_basic() {
        assert_eq!(escape_json("hello"), "hello");
    }

    #[test]
    fn test_escape_json_with_quotes() {
        assert_eq!(escape_json("hello \"world\""), "hello \\\"world\\\"");
    }

    #[test]
    fn test_escape_json_with_backslash() {
        assert_eq!(escape_json("path\\to\\file"), "path\\\\to\\\\file");
    }

    #[test]
    fn test_escape_json_with_newlines() {
        assert_eq!(escape_json("line1\nline2"), "line1\\nline2");
    }

    #[test]
    fn test_escape_json_with_tabs() {
        assert_eq!(escape_json("col1\tcol2"), "col1\\tcol2");
    }

    #[test]
    fn test_parse_and_transform_leetspeak() {
        let json = r#"{"function":"leetspeak","input":"hello"}"#;
        let result = parse_and_transform(json);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("3") || output.contains("0")); // leetspeak converts e->3, o->0
    }

    #[test]
    fn test_parse_and_transform_base64_encode() {
        let json = r#"{"function":"base64_encode","input":"test"}"#;
        let result = parse_and_transform(json);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "dGVzdA==");
    }

    #[test]
    fn test_parse_and_transform_url_encode() {
        let json = r#"{"function":"url_encode","input":"hello world"}"#;
        let result = parse_and_transform(json);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "hello%20world");
    }

    #[test]
    fn test_parse_and_transform_hex_encode() {
        let json = r#"{"function":"hex_encode","input":"test"}"#;
        let result = parse_and_transform(json);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "74657374");
    }

    #[test]
    fn test_parse_and_transform_rot13() {
        let json = r#"{"function":"rot13","input":"hello"}"#;
        let result = parse_and_transform(json);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "uryyb");
    }

    #[test]
    fn test_parse_and_transform_reverse_string() {
        let json = r#"{"function":"reverse_string","input":"hello"}"#;
        let result = parse_and_transform(json);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "olleh");
    }

    #[test]
    fn test_parse_and_transform_to_snake_case() {
        let json = r#"{"function":"to_snake_case","input":"HelloWorld"}"#;
        let result = parse_and_transform(json);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "hello_world");
    }

    #[test]
    fn test_parse_and_transform_to_camel_case() {
        let json = r#"{"function":"to_camel_case","input":"hello_world"}"#;
        let result = parse_and_transform(json);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "helloWorld");
    }

    #[test]
    fn test_parse_and_transform_to_kebab_case() {
        let json = r#"{"function":"to_kebab_case","input":"HelloWorld"}"#;
        let result = parse_and_transform(json);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "hello-world");
    }

    #[test]
    fn test_parse_and_transform_unknown_function() {
        let json = r#"{"function":"unknown_func","input":"test"}"#;
        let result = parse_and_transform(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown function"));
    }

    #[test]
    fn test_parse_and_transform_missing_function() {
        let json = r#"{"input":"test"}"#;
        let result = parse_and_transform(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Missing 'function' field"));
    }

    #[test]
    fn test_parse_and_transform_missing_input() {
        let json = r#"{"function":"leetspeak"}"#;
        let result = parse_and_transform(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Missing 'input' field"));
    }

    #[test]
    fn test_parse_and_transform_case_swap() {
        let json = r#"{"function":"case_swap","input":"Hello"}"#;
        let result = parse_and_transform(json);
        assert!(result.is_ok());
        let output = result.unwrap();
        // case_swap is randomized, just verify it's not empty
        assert!(!output.is_empty());
        assert_eq!(output.len(), 5);
    }

    #[test]
    fn test_parse_and_transform_random_user_agent() {
        let json = r#"{"function":"random_user_agent","input":""}"#;
        let result = parse_and_transform(json);
        assert!(result.is_ok());
        let ua = result.unwrap();
        assert!(!ua.is_empty());
        // User agent should contain Mozilla
        assert!(ua.contains("Mozilla"));
    }

    #[test]
    fn test_parse_and_transform_html_entity_encode() {
        let json = r#"{"function":"html_entity_encode","input":"<script>"}"#;
        let result = parse_and_transform(json);
        assert!(result.is_ok());
        let output = result.unwrap();
        // The function uses hex entities like &#x3C; instead of &lt;
        assert!(output.contains("&#"));
    }

    #[test]
    fn test_parse_and_transform_sql_comment_injection() {
        let json = r#"{"function":"sql_comment_injection","input":"admin"}"#;
        let result = parse_and_transform(json);
        assert!(result.is_ok());
        // Just verify it returns successfully, output may vary
        assert!(!result.unwrap().is_empty());
    }

    #[test]
    fn test_parse_and_transform_domain_typosquat() {
        let json = r#"{"function":"domain_typosquat","input":"example.com"}"#;
        let result = parse_and_transform(json);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(!output.is_empty());
    }

    #[test]
    fn test_parse_and_batch_transform_single() {
        let json = r#"{"transforms":[{"function":"reverse_string","input":"hello"}]}"#;
        let result = parse_and_batch_transform(json);
        assert!(result.is_ok());
        let outputs = result.unwrap();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0], "olleh");
    }

    #[test]
    fn test_parse_and_batch_transform_multiple() {
        let json = r#"{"transforms":[{"function":"reverse_string","input":"hello"},{"function":"rot13","input":"hello"}]}"#;
        let result = parse_and_batch_transform(json);
        assert!(result.is_ok());
        let outputs = result.unwrap();
        assert_eq!(outputs.len(), 2);
        assert_eq!(outputs[0], "olleh");
        assert_eq!(outputs[1], "uryyb");
    }

    #[test]
    fn test_parse_and_batch_transform_empty() {
        let json = r#"{"transforms":[]}"#;
        let result = parse_and_batch_transform(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_and_batch_transform_missing_transforms() {
        let json = r#"{"data":[]}"#;
        let result = parse_and_batch_transform(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_and_batch_transform_invalid_function() {
        let json = r#"{"transforms":[{"function":"invalid_func","input":"test"}]}"#;
        let result = parse_and_batch_transform(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_json_field_empty_string() {
        let json = r#"{"function":"test","input":""}"#;
        assert_eq!(extract_json_field(json, "input"), Some("".to_string()));
    }

    #[test]
    fn test_parse_and_batch_transform_with_whitespace() {
        // Test with whitespace after colon
        let json = r#"{"transforms": [{"function":"reverse_string","input":"hello"}]}"#;
        let result = parse_and_batch_transform(json);
        assert!(result.is_ok());
        let outputs = result.unwrap();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0], "olleh");
    }

    #[test]
    fn test_get_timestamp() {
        let timestamp = get_timestamp();
        // Timestamp should be a reasonable value (after year 2020)
        assert!(timestamp > 1577836800000); // Jan 1, 2020 in milliseconds
    }

    #[test]
    fn test_extract_method_and_path_get() {
        let request = "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let (method, path) = extract_method_and_path(request);
        assert_eq!(method, "GET");
        assert_eq!(path, "/health");
    }

    #[test]
    fn test_extract_method_and_path_post() {
        let request = "POST /transform HTTP/1.1\r\nHost: localhost\r\n\r\n{\"test\":\"data\"}";
        let (method, path) = extract_method_and_path(request);
        assert_eq!(method, "POST");
        assert_eq!(path, "/transform");
    }

    #[test]
    fn test_extract_method_and_path_empty() {
        let request = "";
        let (method, path) = extract_method_and_path(request);
        assert_eq!(method, "UNKNOWN");
        assert_eq!(path, "UNKNOWN");
    }

    #[test]
    fn test_extract_method_and_path_incomplete() {
        let request = "GET";
        let (method, path) = extract_method_and_path(request);
        assert_eq!(method, "GET");
        assert_eq!(path, "UNKNOWN");
    }
}

