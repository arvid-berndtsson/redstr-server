use std::io::{Read, Write};
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

/// Helper function to send HTTP POST request and get response
fn send_post_request(path: &str, body: &str) -> String {
    // Give server time to start if needed
    thread::sleep(Duration::from_millis(100));
    
    let mut stream = TcpStream::connect("127.0.0.1:8080")
        .expect("Failed to connect to server");
    
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: localhost:8080\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        path, body.len(), body
    );
    
    stream.write_all(request.as_bytes())
        .expect("Failed to write to stream");
    
    let mut buffer = vec![0u8; 4096];
    let size = stream.read(&mut buffer)
        .expect("Failed to read from stream");
    
    String::from_utf8_lossy(&buffer[..size]).to_string()
}

/// Helper function to send HTTP GET request and get response
fn send_get_request(path: &str) -> String {
    // Give server time to start if needed
    thread::sleep(Duration::from_millis(100));
    
    let mut stream = TcpStream::connect("127.0.0.1:8080")
        .expect("Failed to connect to server");
    
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: localhost:8080\r\n\r\n",
        path
    );
    
    stream.write_all(request.as_bytes())
        .expect("Failed to write to stream");
    
    let mut buffer = vec![0u8; 4096];
    let size = stream.read(&mut buffer)
        .expect("Failed to read from stream");
    
    String::from_utf8_lossy(&buffer[..size]).to_string()
}

/// Extract body from HTTP response
fn extract_body(response: &str) -> String {
    if let Some(body_start) = response.find("\r\n\r\n") {
        response[body_start + 4..].to_string()
    } else {
        String::new()
    }
}

#[test]
#[ignore] // Ignore by default as it requires server to be running
fn test_health_endpoint() {
    let response = send_get_request("/health");
    assert!(response.contains("200 OK"));
    let body = extract_body(&response);
    assert!(body.contains(r#""status":"healthy""#));
}

#[test]
#[ignore] // Ignore by default as it requires server to be running
fn test_root_endpoint() {
    let response = send_get_request("/");
    assert!(response.contains("200 OK"));
    let body = extract_body(&response);
    assert!(body.contains(r#""service":"redstr""#));
    assert!(body.contains(r#""version":"0.2.0""#));
    assert!(body.contains(r#""endpoints""#));
}

#[test]
#[ignore] // Ignore by default as it requires server to be running
fn test_transform_leetspeak() {
    let body = r#"{"function":"leetspeak","input":"hello"}"#;
    let response = send_post_request("/transform", body);
    assert!(response.contains("200 OK"));
    let response_body = extract_body(&response);
    assert!(response_body.contains(r#""output""#));
}

#[test]
#[ignore] // Ignore by default as it requires server to be running
fn test_transform_base64_encode() {
    let body = r#"{"function":"base64_encode","input":"test"}"#;
    let response = send_post_request("/transform", body);
    assert!(response.contains("200 OK"));
    let response_body = extract_body(&response);
    assert!(response_body.contains(r#""output":"dGVzdA==""#));
}

#[test]
#[ignore] // Ignore by default as it requires server to be running
fn test_transform_url_encode() {
    let body = r#"{"function":"url_encode","input":"hello world"}"#;
    let response = send_post_request("/transform", body);
    assert!(response.contains("200 OK"));
    let response_body = extract_body(&response);
    assert!(response_body.contains(r#""output":"hello%20world""#));
}

#[test]
#[ignore] // Ignore by default as it requires server to be running
fn test_transform_hex_encode() {
    let body = r#"{"function":"hex_encode","input":"test"}"#;
    let response = send_post_request("/transform", body);
    assert!(response.contains("200 OK"));
    let response_body = extract_body(&response);
    assert!(response_body.contains(r#""output":"74657374""#));
}

#[test]
#[ignore] // Ignore by default as it requires server to be running
fn test_transform_rot13() {
    let body = r#"{"function":"rot13","input":"hello"}"#;
    let response = send_post_request("/transform", body);
    assert!(response.contains("200 OK"));
    let response_body = extract_body(&response);
    assert!(response_body.contains(r#""output":"uryyb""#));
}

#[test]
#[ignore] // Ignore by default as it requires server to be running
fn test_transform_reverse_string() {
    let body = r#"{"function":"reverse_string","input":"hello"}"#;
    let response = send_post_request("/transform", body);
    assert!(response.contains("200 OK"));
    let response_body = extract_body(&response);
    assert!(response_body.contains(r#""output":"olleh""#));
}

#[test]
#[ignore] // Ignore by default as it requires server to be running
fn test_transform_unknown_function() {
    let body = r#"{"function":"unknown_function","input":"test"}"#;
    let response = send_post_request("/transform", body);
    assert!(response.contains("400 Bad Request"));
    let response_body = extract_body(&response);
    assert!(response_body.contains(r#""error""#));
    assert!(response_body.contains("Unknown function"));
}

#[test]
#[ignore] // Ignore by default as it requires server to be running
fn test_transform_missing_function() {
    let body = r#"{"input":"test"}"#;
    let response = send_post_request("/transform", body);
    assert!(response.contains("400 Bad Request"));
    let response_body = extract_body(&response);
    assert!(response_body.contains(r#""error""#));
}

#[test]
#[ignore] // Ignore by default as it requires server to be running
fn test_transform_missing_input() {
    let body = r#"{"function":"leetspeak"}"#;
    let response = send_post_request("/transform", body);
    assert!(response.contains("400 Bad Request"));
    let response_body = extract_body(&response);
    assert!(response_body.contains(r#""error""#));
}

#[test]
#[ignore] // Ignore by default as it requires server to be running
fn test_cors_header_present() {
    let response = send_get_request("/health");
    assert!(response.contains("Access-Control-Allow-Origin: *"));
}

#[test]
#[ignore] // Ignore by default as it requires server to be running
fn test_not_found_endpoint() {
    let response = send_get_request("/nonexistent");
    assert!(response.contains("404 Not Found"));
}

#[test]
#[ignore] // Ignore by default as it requires server to be running
fn test_transform_case_transformations() {
    let test_cases = vec![
        ("to_snake_case", "HelloWorld", "hello_world"),
        ("to_camel_case", "hello_world", "helloWorld"),
        ("to_kebab_case", "HelloWorld", "hello-world"),
        ("case_swap", "Hello", "hELLO"),
    ];
    
    for (function, input, expected) in test_cases {
        let body = format!(r#"{{"function":"{}","input":"{}"}}"#, function, input);
        let response = send_post_request("/transform", &body);
        assert!(response.contains("200 OK"), "Failed for function: {}", function);
        let response_body = extract_body(&response);
        assert!(response_body.contains(&format!(r#""output":"{}""#, expected)), 
                "Failed for function: {}, expected: {}", function, expected);
    }
}

#[test]
#[ignore] // Ignore by default as it requires server to be running
fn test_transform_with_special_characters() {
    let body = r#"{"function":"reverse_string","input":"hello\nworld"}"#;
    let response = send_post_request("/transform", body);
    assert!(response.contains("200 OK"));
    let response_body = extract_body(&response);
    assert!(response_body.contains(r#""output""#));
}

#[test]
#[ignore] // Ignore by default as it requires server to be running
fn test_transform_random_user_agent() {
    let body = r#"{"function":"random_user_agent","input":""}"#;
    let response = send_post_request("/transform", body);
    assert!(response.contains("200 OK"));
    let response_body = extract_body(&response);
    assert!(response_body.contains(r#""output""#));
    // User agent should not be empty
    assert!(!response_body.contains(r#""output":""}"#));
}

#[test]
#[ignore] // Ignore by default as it requires server to be running
fn test_multiple_sequential_requests() {
    for i in 0..5 {
        let body = format!(r#"{{"function":"reverse_string","input":"test{}"}}"#, i);
        let response = send_post_request("/transform", &body);
        assert!(response.contains("200 OK"), "Request {} failed", i);
    }
}

#[test]
#[ignore] // Ignore by default as it requires server to be running
fn test_functions_endpoint() {
    let response = send_get_request("/functions");
    assert!(response.contains("200 OK"));
    let body = extract_body(&response);
    assert!(body.contains(r#""functions""#));
    assert!(body.contains(r#""count""#));
    // Check for some known functions
    assert!(body.contains("leetspeak"));
    assert!(body.contains("base64_encode"));
    assert!(body.contains("reverse_string"));
}

#[test]
#[ignore] // Ignore by default as it requires server to be running
fn test_version_endpoint() {
    let response = send_get_request("/version");
    assert!(response.contains("200 OK"));
    let body = extract_body(&response);
    assert!(body.contains(r#""service":"redstr-server""#));
    assert!(body.contains(r#""version":"0.1.0""#));
    assert!(body.contains(r#""redstr_version":"0.2.0""#));
}

#[test]
#[ignore] // Ignore by default as it requires server to be running
fn test_batch_transform_single() {
    let body = r#"{"transforms":[{"function":"reverse_string","input":"hello"}]}"#;
    let response = send_post_request("/batch", body);
    assert!(response.contains("200 OK"));
    let response_body = extract_body(&response);
    assert!(response_body.contains(r#""results""#));
    assert!(response_body.contains(r#""output":"olleh""#));
}

#[test]
#[ignore] // Ignore by default as it requires server to be running
fn test_batch_transform_multiple() {
    let body = r#"{"transforms":[{"function":"reverse_string","input":"hello"},{"function":"rot13","input":"hello"}]}"#;
    let response = send_post_request("/batch", body);
    assert!(response.contains("200 OK"));
    let response_body = extract_body(&response);
    assert!(response_body.contains(r#""results""#));
    assert!(response_body.contains(r#""output":"olleh""#));
    assert!(response_body.contains(r#""output":"uryyb""#));
}

#[test]
#[ignore] // Ignore by default as it requires server to be running
fn test_batch_transform_empty() {
    let body = r#"{"transforms":[]}"#;
    let response = send_post_request("/batch", body);
    assert!(response.contains("400 Bad Request"));
    let response_body = extract_body(&response);
    assert!(response_body.contains(r#""error""#));
}

#[test]
#[ignore] // Ignore by default as it requires server to be running
fn test_root_endpoint_has_all_endpoints() {
    let response = send_get_request("/");
    assert!(response.contains("200 OK"));
    let body = extract_body(&response);
    assert!(body.contains("/transform"));
    assert!(body.contains("/batch"));
    assert!(body.contains("/functions"));
    assert!(body.contains("/health"));
    assert!(body.contains("/version"));
}
