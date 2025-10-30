// Enhanced HTTP proxy with rule-based filtering
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Client, Request, Response, Server, Uri};
use rocket_dispatch_utils::proxy::{ProxyCondition, ProxyAction};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use http_proxy_monitor::monitor::Monitor;
use hyper::http::uri::Authority;




#[tokio::main]
async fn main() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 8888));

    let monitor = Monitor::new().add_rule(
        // Example rule: Allow requests to example.com on ports 1000 or 2000
        vec!
        [
            ProxyCondition::Domain { domain: "example.com".to_string() },
            ProxyCondition::Port { ports: vec![1000, 2000] }
        ]
    ).add_rule(
        // Example rule: Allow S3 health check requests
        vec![
            ProxyCondition::Domain { domain: "172.27.75.74".to_string() },
            ProxyCondition::Port { ports: vec![9000] },
            ProxyCondition::Path { path: "/minio/health/live".to_string() }
        ]
    ).add_rule(
        // Example rule: Allow S3 list bucket requests
        vec![
            ProxyCondition::Domain { domain: "172.27.75.74".to_string() },
            ProxyCondition::Method { methods: vec!["GET".to_string()] },
            ProxyCondition::Port { ports: vec![9000] },
            ProxyCondition::Path { path: "/".to_string() },
            ProxyCondition::Query { query: "x-id=ListBuckets".to_string() }
        ]
    ).add_rule(
        // Example rule: Allow S3 bucket access requests (only to /general/)
        vec![
            ProxyCondition::Domain { domain: "172.27.75.74".to_string() },
            ProxyCondition::Method { methods: vec!["HEAD".to_string()] },
            ProxyCondition::Port { ports: vec![9000] },
            ProxyCondition::PathNotContains { pattern: "secret".to_string() }
        ]
    ).add_rule(
        // Example rule: Allow S3 upload file request
        vec![

            ProxyCondition::Domain { domain: "172.27.75.74".to_string() },
            ProxyCondition::Method { methods: vec!["PUT".to_string()] },
            ProxyCondition::Port { ports: vec![9000] },
            ProxyCondition::Query { query: "x-id=PutObject".to_string() },
            ProxyCondition::PathNotContains { pattern: "secret".to_string() }
        ]
    ).add_rule(
        // Example rule: Allow GET requests to httpbin.org/get without "admin" in query
        vec![
            ProxyCondition::Domain { domain: "httpbin.org".to_string() },
            ProxyCondition::Path { path: "/get".to_string() },
            ProxyCondition::Method { methods: vec!["GET".to_string()] },
            ProxyCondition::QueryNotContains { pattern: "admin".to_string() }
        ]
    );

    let monitor = Arc::new(monitor);

    let make_svc = make_service_fn(move |_conn| {
        // This closure runs ONCE per TCP connection
        // _conn contains connection info (IP address, etc.)
        let monitor = monitor.clone();  // Clone shared state for this connection
        
        async move {
            // Return a "service" that will handle requests on this connection
            Ok::<_, Infallible>(service_fn(move |req| {
                // This closure runs ONCE per HTTP request
                let monitor = monitor.clone();  // Clone for this specific request
                proxy_handler(req, monitor)     // Your actual request handler
            }))
        }
    });

    let server = Server::bind(&addr).serve(make_svc);
    println!("Monitor running on http://{}", addr);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}

async fn proxy_handler(
    req: Request<Body>,
    monitor: Arc<Monitor>,
) -> Result<Response<Body>, Infallible> {
    println!("[proxy] ========== NEW REQUEST ==========");
    println!("[proxy] Method: {}", req.method());
    let domain_from_host = req.headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.parse::<Authority>().ok())
        .map(|auth| auth.host().to_string());
    println!("[proxy] Domain from Host header: {:?}", domain_from_host);
    println!("[proxy] Path: {}", req.uri().path());
    println!("[proxy] Query: {:?}", req.uri().query());
    println!("[proxy] Full URI: {}", req.uri());

    
    // Destructure the request to get ownership of the body
    let (parts, body) = req.into_parts();
    let whole_body = hyper::body::to_bytes(body).await.unwrap_or_default();
    println!("[proxy] Body: {:?}", String::from_utf8_lossy(&whole_body));

    // Reconstruct the request with the consumed body
    let req = Request::from_parts(parts, Body::from(whole_body));

    // Evaluate proxy rules
    let action = monitor.evaluate_rules(&req);
    println!("[proxy] Rule evaluation result: {:?}", action);

    match action {
        ProxyAction::Allow => {
            println!("[proxy] ✅ Request ALLOWED, forwarding");
            forward_request(req).await
        }
        ProxyAction::Deny => {
            println!("[proxy] ❌ Request DENIED by rules");
            Ok(Response::builder()
                .status(403)
                .body(Body::from("Request blocked by proxy rules"))
                .unwrap())
        }
    }
}

async fn forward_request(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    let client = Client::new();

    // Build the destination URI
    let scheme = req.uri().scheme_str().unwrap_or("http");
    let authority = req.uri().authority().map(|a| a.as_str()).unwrap_or("");
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let uri_string = format!("{}://{}{}", scheme, authority, path_and_query);
    let uri: Uri = uri_string
        .parse()
        .unwrap_or_else(|_| "http://example.com/".parse().unwrap());

    println!("[proxy] Forwarding to: {}", uri);

    let headers = req.headers().clone();
    let mut new_req = Request::builder()
        .method(req.method())
        .uri(uri)
        .body(req.into_body())
        .unwrap();
    *new_req.headers_mut() = headers;

    match client.request(new_req).await {
        Ok(resp) => {
            println!("[proxy] Got response with status: {}", resp.status());
            Ok(resp)
        }
        Err(e) => {
            println!("[proxy] Error forwarding request: {}", e);
            Ok(Response::builder()
                .status(502)
                .body(Body::from("Bad Gateway"))
                .unwrap())
        }
    }
}
