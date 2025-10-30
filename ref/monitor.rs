use hyper::http::uri::Authority;
use hyper::{Body, Client, Request, Response, Server, Uri};
use rocket_dispatch_utils::proxy::{ProxyAction, ProxyCondition, ProxyRule};

pub struct Monitor {
    rules: Vec<ProxyRule>,
}

impl Monitor {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(mut self, conditions: Vec<ProxyCondition>) -> Self {
        self.rules.push(ProxyRule { conditions });
        self
    }

    pub fn add_rules(mut self, rules: Vec<ProxyRule>) {
        self.rules.extend(rules);
    }

    pub fn evaluate_rules(&self, req: &Request<Body>) -> ProxyAction {
        for rule in &self.rules {
            match rule_matches(rule, req) {
                true => return ProxyAction::Allow,
                false => continue,
            }
        }
        ProxyAction::Deny
    }
}

fn rule_matches(rule: &ProxyRule, req: &Request<Body>) -> bool {
    for condition in &rule.conditions {
        match condition_matches(condition, req) {
            Ok(true) => continue,
            Ok(false) => return false,
            Err(err_message) => {
                println!("Error evaluating condition: {}", err_message);
                println!("Defaulting to condition not met");
                return false;
            },
        }
    }
    true
}

fn condition_matches(condition: &ProxyCondition, req: &Request<Body>) -> Result<bool, String> {
    match condition {
        // Method conditions
        ProxyCondition::Method { methods } => Ok(methods.contains(&req.method().to_string())),
        ProxyCondition::MethodNot { methods } => Ok(!methods.contains(&req.method().to_string())),

        // Domain conditions
        ProxyCondition::Domain { domain } => {
            let host = req
                .headers()
                .get("host")
                .ok_or("Request missing Host header")?
                .to_str()
                .map_err(|_| "Host header contains invalid UTF-8")?
                .parse::<Authority>()
                .map_err(|_| "Host header is not a valid authority")?;
            Ok(host.host() == domain)
        }
        ProxyCondition::DomainNot { domain } => {
            let host = req
                .headers()
                .get("host")
                .ok_or("Request missing Host header")?
                .to_str()
                .map_err(|_| "Host header contains invalid UTF-8")?
                .parse::<Authority>()
                .map_err(|_| "Host header is not a valid authority")?;

            Ok(host.host() != domain)
        }

        // Domain contains conditions
        ProxyCondition::DomainContains { pattern } => {
            let authority = req
                .uri()
                .authority()
                .ok_or("Request URI missing authority")?;

            Ok(authority.host().contains(pattern))
        }
        ProxyCondition::DomainNotContains { pattern } => {
            let authority = req
                .uri()
                .authority()
                .ok_or("Request URI missing authority")?;

            Ok(!authority.host().contains(pattern))
        }

        // Path conditions
        ProxyCondition::Path { path } => Ok(req.uri().path() == path),
        ProxyCondition::PathNot { path } => Ok(req.uri().path() != path),

        // Path contains conditions
        ProxyCondition::PathContains { pattern } => Ok(req.uri().path().contains(pattern)),
        ProxyCondition::PathNotContains { pattern } => Ok(!req.uri().path().contains(pattern)),

        // Query conditions
        ProxyCondition::Query { query } => {
            let query_str = req.uri().query().ok_or("Request URI has no query string")?;
            Ok(query_str == query)
        }
        ProxyCondition::QueryNot { query } => {
            let query_str = req.uri().query().ok_or("Request URI has no query string")?;
            Ok(query_str != query)
        }

        // Query contains conditions
        ProxyCondition::QueryContains { pattern } => {
            let query = req.uri().query().ok_or("Request URI has no query string")?;
            Ok(query.contains(pattern))
        }
        ProxyCondition::QueryNotContains { pattern } => {
            let query = req.uri().query().ok_or("Request URI has no query string")?;

            Ok(!query.contains(pattern))
        }

        // Header contains conditions
        ProxyCondition::HeaderContains { name, value } => {
            let header_value = req
                .headers()
                .get(name)
                .ok_or_else(|| format!("Request missing header: {}", name))?
                .to_str()
                .map_err(|_| format!("Header '{}' contains invalid UTF-8", name))?;

            Ok(header_value.contains(value))
        }
        ProxyCondition::HeaderNotContains { name, value } => {
            let header_value = req
                .headers()
                .get(name)
                .ok_or_else(|| format!("Request missing header: {}", name))?
                .to_str()
                .map_err(|_| format!("Header '{}' contains invalid UTF-8", name))?;

            Ok(!header_value.contains(value))
        }

        // Body contains conditions
        ProxyCondition::BodyContains { .. } => {
            Err("Body condition matching not implemented - requires body parsing".to_string())
        }
        ProxyCondition::BodyNotContains { .. } => {
            Err("Body condition matching not implemented - requires body parsing".to_string())
        }

        // Port conditions
        ProxyCondition::Port { ports } => {
            let port = req
                .uri()
                .port_u16()
                .ok_or("Request URI has no port specified")?;

            Ok(ports.contains(&port))
        }
        ProxyCondition::PortNot { ports } => {
            let port = req
                .uri()
                .port_u16()
                .ok_or("Request URI has no port specified")?;

            Ok(!ports.contains(&port))
        }

        // Protocol conditions
        ProxyCondition::Protocol { protocols } => {
            let scheme = req
                .uri()
                .scheme_str()
                .ok_or("Request URI has no scheme specified")?;

            Ok(protocols.contains(&scheme.to_string()))
        }
        ProxyCondition::ProtocolNot { protocols } => {
            let scheme = req
                .uri()
                .scheme_str()
                .ok_or("Request URI has no scheme specified")?;

            Ok(!protocols.contains(&scheme.to_string()))
        }
    }
}
