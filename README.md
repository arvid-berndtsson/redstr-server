# redstr-server

A high-performance HTTP API server for [redstr](https://github.com/arvid-berndtsson/redstr) string transformations. Built with Axum, this server provides a modern, async REST API that allows external tools to use redstr's transformation functions over HTTP.

## Features

- ⚡ **High Performance** - Built on Axum and Tokio for async I/O
- 🚀 **Serverless Ready** - Compatible with Railway and other serverless platforms
- 📝 **Structured Logging** - Professional logging with tracing and request tracking
- 🔄 **Type-Safe** - Leverages Rust's type system with Serde for JSON handling
- 🌐 **CORS Enabled** - Full CORS support for browser access
- 📊 **Request Tracing** - Automatic request/response logging with latency tracking
- 🛡️ **Modern Stack** - Axum, Tower, Tokio, and Serde

## Prerequisites

- Rust 1.70+ installed
- Access to the [redstr](https://github.com/arvid-berndtsson/redstr) core library (as a dependency)

## Installation

```bash
git clone https://github.com/arvid-berndtsson/redstr-server.git
cd redstr-server
cargo build --release
```

The binary will be available at `target/release/redstr-server`.

## Usage

Start the server:

```bash
cargo run --release
```

Or run the compiled binary:

```bash
./target/release/redstr-server
```

The server will listen on `http://127.0.0.1:8080` by default.

## API Endpoints

### GET /

Returns server information and available endpoints.

**Response:**
```json
{
  "service": "redstr",
  "version": "0.2.0",
  "endpoints": ["/transform", "/batch", "/functions", "/health", "/version"]
}
```

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy"
}
```

### GET /version

Get detailed version information.

**Response:**
```json
{
  "service": "redstr-server",
  "version": "0.1.0",
  "redstr_version": "0.2.0"
}
```

### GET /functions

List all available transformation functions.

**Response:**
```json
{
  "functions": ["leetspeak", "base64_encode", "url_encode", ...],
  "count": 62
}
```

### POST /transform

Transform a string using a redstr function.

**Request:**
```json
{
  "function": "leetspeak",
  "input": "Hello World"
}
```

**Response:**
```json
{
  "output": "H3ll0 W0rld"
}
```

**Error Response:**
```json
{
  "error": "Unknown function: invalid_function"
}
```

### POST /batch

Transform multiple strings in a single request.

**Request:**
```json
{
  "transforms": [
    {"function": "leetspeak", "input": "Hello"},
    {"function": "base64_encode", "input": "World"}
  ]
}
```

**Response:**
```json
{
  "results": [
    {"output": "H3ll0"},
    {"output": "V29ybGQ="}
  ]
}
```

## Available Functions

See the [redstr documentation](https://github.com/arvid-berndtsson/redstr) for a complete list of available transformation functions. All redstr functions are available via the API.

## Example Usage

### Using curl

```bash
# List all available functions
curl http://localhost:8080/functions

# Check server health
curl http://localhost:8080/health

# Get version information
curl http://localhost:8080/version

# Basic transformation
curl -X POST http://localhost:8080/transform \
  -H "Content-Type: application/json" \
  -d '{"function":"leetspeak","input":"password"}'

# Batch transformations
curl -X POST http://localhost:8080/batch \
  -H "Content-Type: application/json" \
  -d '{"transforms":[{"function":"leetspeak","input":"hello"},{"function":"base64_encode","input":"world"}]}'

# SQL injection pattern
curl -X POST http://localhost:8080/transform \
  -H "Content-Type: application/json" \
  -d '{"function":"sql_comment_injection","input":"SELECT * FROM users"}'

# Domain typosquatting
curl -X POST http://localhost:8080/transform \
  -H "Content-Type: application/json" \
  -d '{"function":"domain_typosquat","input":"example.com"}'
```

### Using Python

```python
import requests

url = "http://localhost:8080/transform"
payload = {
    "function": "xss_tag_variations",
    "input": "<script>alert('XSS')</script>"
}

response = requests.post(url, json=payload)
print(response.json()["output"])
```

### Using JavaScript

```javascript
fetch('http://localhost:8080/transform', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    function: 'base64_encode',
    input: 'Hello World'
  })
})
.then(res => res.json())
.then(data => console.log(data.output));
```

## Integration with External Tools

This HTTP server is designed to be used as a bridge between redstr and external security testing tools:

- **EvilJinx**: Use for domain generation and email obfuscation
- **Caido**: Create plugins that call this API for transformations
- **Burp Suite**: Build extensions that interface with this server
- **OWASP ZAP**: Create add-ons that use this API
- **Custom Tools**: Any tool that can make HTTP requests

## Security Considerations

- The server binds to localhost (127.0.0.1) by default for security
- No authentication is implemented - add your own if exposing to network
- Designed for local use and authorized security testing only
- Log all transformation requests for audit purposes

## Performance

- **Async I/O** - Built on Tokio for high concurrency
- **Low Latency** - Sub-millisecond response times
- **Scalable** - Handles thousands of concurrent connections
- **Memory Efficient** - Minimal memory footprint per request
- **Production Ready** - Battle-tested Axum framework

## Troubleshooting

**Port already in use:**
```
Error: Address already in use (os error 98)
```
Solution: Change the port in `main.rs` or kill the process using port 8080.

**Connection refused:**
Ensure the server is running and accessible at the configured address.

## Testing

The project includes comprehensive unit and integration tests.

### Run Unit Tests

```bash
cargo test --bin redstr-server
```

### Run Integration Tests

Integration tests require the server to be running. Start the server in one terminal:

```bash
cargo run --release
```

Then in another terminal, run the integration tests:

```bash
cargo test --test integration_tests -- --ignored
```

## Logging

The server provides comprehensive structured logging in **JSON format** using Rust's `tracing` framework, fully compatible with [Railway's log filtering](https://docs.railway.com/guides/logs#filtering-logs).

### Log Format

All logs are output as JSON objects with structured fields for easy filtering and analysis:

```json
{
  "timestamp": "2025-11-25T16:10:22.262009Z",
  "level": "ERROR",
  "fields": {
    "message": "Transformation failed",
    "function": "invalid",
    "error": "Unknown function: invalid"
  },
  "target": "redstr_server",
  "span": {
    "method": "POST",
    "uri": "/transform",
    "version": "HTTP/1.1",
    "name": "request"
  }
}
```

### Log Levels

Control logging verbosity with the `RUST_LOG` environment variable:

```bash
# Show all logs (default)
RUST_LOG=info cargo run

# Show only warnings and errors
RUST_LOG=warn cargo run

# Show only errors
RUST_LOG=error cargo run

# Show debug logs (verbose)
RUST_LOG=debug cargo run
```

### Railway Log Filtering

Use Railway's powerful filtering syntax with the JSON log attributes:

**Filter by log level:**
- `@level:ERROR` - Show only errors
- `@level:INFO` - Show info logs
- `@level:DEBUG` - Show debug logs

**Filter by custom fields:**
- `@fields.function:leetspeak` - Show logs for specific transformation
- `@fields.status:400` - Show specific status codes
- `@fields.error:*` - Show all logs with error field
- `@span.uri:/transform` - Show logs for specific endpoint
- `@span.method:POST` - Show POST requests only

**Combine filters:**
- `@level:ERROR AND @span.uri:/transform` - Show errors on /transform endpoint
- `@level:INFO AND @fields.function:*` - Show info logs with function field
- `"Unknown function"` - Text search within log messages

**Examples:**
```
@level:ERROR                           # All errors
@fields.function:reverse_string        # Specific function
@span.uri:/batch                       # Batch endpoint logs
@level:ERROR AND @span.uri:/transform  # Transform errors only
```

### What Gets Logged

✅ **Request Start** - Method, URI, HTTP version  
✅ **Request Processing** - Function name, operation details  
✅ **Request Completion** - Latency, status code  
✅ **Transformation Success** - Function name and confirmation  
✅ **All Errors** - Detailed error messages with context  
✅ **Batch Operations** - Count of operations processed

## Technology Stack

- **[Axum](https://github.com/tokio-rs/axum)** - Web framework
- **[Tokio](https://tokio.rs/)** - Async runtime
- **[Tower](https://github.com/tower-rs/tower)** - Middleware and service abstractions
- **[Serde](https://serde.rs/)** - JSON serialization/deserialization
- **[Tracing](https://tracing.rs/)** - Structured logging and diagnostics

## Future Enhancements

- [ ] Configuration file support
- [x] Environment-based port binding (✅ Supports PORT env var)
- [ ] Authentication/authorization with JWT
- [ ] Rate limiting middleware
- [x] Request logging (✅ Completed with tracing)
- [ ] Metrics endpoint (Prometheus format)
- [x] Async I/O (✅ Completed with Tokio)
- [ ] TLS support
- [ ] OpenAPI/Swagger documentation

## License

MIT License - See LICENSE file in the repository root.

---

**Important:** This server is designed for authorized security testing only. Users must obtain proper authorization before conducting any security assessments.

