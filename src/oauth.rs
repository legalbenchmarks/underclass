//! Safe diagnostics for unsuccessful OAuth token responses.

use reqwest::Response;
use serde_json::{Value, json};
use std::time::Duration;

const BODY_LIMIT: usize = 2048;
const REDACTED: &str = "[REDACTED]";

/// Only sanitized diagnostics are stored, including in `Debug` and `Display` output.
#[derive(Debug, thiserror::Error)]
#[error("unexpected status {status}: {body_excerpt}")]
pub struct TokenEndpointError {
    status: u16,
    error: Option<String>,
    error_description: Option<String>,
    body_excerpt: String,
}

impl TokenEndpointError {
    pub fn status(&self) -> u16 {
        self.status
    }

    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    pub fn error_description(&self) -> Option<&str> {
        self.error_description.as_deref()
    }

    pub fn body_excerpt(&self) -> &str {
        &self.body_excerpt
    }

    /// @cc [owner:ghuntley,label:security] bounded-token-error-response
    /// Failed token requests MUST retain their HTTP status even if reading the body fails.
    /// Diagnostics MUST retain at most 2048 response bytes, wait at most two seconds for the body,
    /// and sanitize before storing or exposing any response text.
    pub async fn from_response(mut response: Response, secrets: &[&str]) -> Self {
        let status = response.status().as_u16();
        let mut body = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(2), async {
            while let Some(chunk) = response.chunk().await? {
                let remaining = BODY_LIMIT - body.len();
                body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
                if chunk.len() >= remaining {
                    return Ok::<_, reqwest::Error>(false);
                }
            }
            Ok(true)
        })
        .await;
        if !matches!(read, Ok(Ok(true))) {
            return Self::omitted(status, "[REDACTED: incomplete token endpoint response]");
        }
        Self::from_body(status, &body, secrets)
    }

    /// @cc [owner:ghuntley,label:security] token-error-allowlist
    /// Only JSON string fields `error` and `error_description` MAY survive in diagnostics.
    /// Request secrets, other JSON values echoed in those fields, credential assignments and
    /// token-shaped words MUST be redacted. Malformed/non-JSON bodies MUST be omitted entirely.
    /// The extracted error, description and body excerpt MUST each be bounded to 2048 bytes,
    /// on a UTF-8 boundary.
    pub fn from_body(status: u16, body: &[u8], secrets: &[&str]) -> Self {
        if body.len() >= BODY_LIMIT {
            return Self::omitted(status, "[REDACTED: incomplete token endpoint response]");
        }
        let Ok(Value::Object(object)) = serde_json::from_slice::<Value>(body) else {
            return Self::omitted(status, "[REDACTED: non-JSON token endpoint response]");
        };
        let mut secrets: Vec<String> = secrets.iter().map(|s| (*s).to_owned()).collect();
        for (key, value) in &object {
            if !matches!(key.as_str(), "error" | "error_description") {
                secrets.push(key.clone());
                collect_secrets(value, &mut secrets);
            }
        }
        let field = |key| {
            object
                .get(key)
                .and_then(Value::as_str)
                .map(|s| sanitize(s, &secrets))
        };
        let error = field("error");
        let error_description = field("error_description");
        let mut excerpt = serde_json::Map::new();
        if let Some(error) = &error {
            excerpt.insert("error".into(), json!(error));
        }
        if let Some(description) = &error_description {
            excerpt.insert("error_description".into(), json!(description));
        }
        if object.len() != excerpt.len() {
            excerpt.insert("other_fields".into(), json!(REDACTED));
        }
        Self {
            status,
            error,
            error_description,
            body_excerpt: bounded(Value::Object(excerpt).to_string()),
        }
    }

    fn omitted(status: u16, reason: &str) -> Self {
        Self {
            status,
            error: None,
            error_description: None,
            body_excerpt: reason.into(),
        }
    }
}

fn collect_secrets(value: &Value, secrets: &mut Vec<String>) {
    match value {
        Value::String(s) => secrets.push(s.clone()),
        Value::Number(n) => secrets.push(n.to_string()),
        Value::Array(values) => values.iter().for_each(|v| collect_secrets(v, secrets)),
        Value::Object(object) => {
            for (key, value) in object {
                secrets.push(key.clone());
                collect_secrets(value, secrets);
            }
        }
        _ => {}
    }
}

fn sanitize(text: &str, secrets: &[String]) -> String {
    let mut text = text.to_owned();
    // Redact known values before scanning words, including short codes and echoed request secrets.
    let mut secrets: Vec<_> = secrets.iter().filter(|s| !s.is_empty()).collect();
    secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
    for secret in secrets {
        text = text.replace(secret, REDACTED);
    }
    // An assignment or Bearer header can contain a short, otherwise unrecognizable credential.
    let lower = text.to_ascii_lowercase();
    let mut cutoff = None;
    for key in [
        "access_token",
        "refresh_token",
        "id_token",
        "code",
        "code_verifier",
        "authorization",
        "bearer",
    ] {
        for (start, _) in lower.match_indices(key) {
            let end = start + key.len();
            let boundary = start == 0
                || !(lower.as_bytes()[start - 1].is_ascii_alphanumeric()
                    || lower.as_bytes()[start - 1] == b'_');
            let tail = &lower[end..];
            let assignment = tail
                .trim_start()
                .trim_start_matches(['\'', '"'])
                .trim_start()
                .starts_with(['=', ':']);
            let bearer =
                key == "bearer" && tail.as_bytes().first().is_some_and(u8::is_ascii_whitespace);
            if boundary && (assignment || bearer) {
                cutoff = Some(cutoff.map_or(end, |old: usize| old.min(end)));
            }
        }
    }
    if let Some(cutoff) = cutoff {
        text.truncate(cutoff);
        text.push_str(REDACTED);
    }
    let mut safe = String::new();
    for word in
        text.split_inclusive(|c: char| !(c.is_ascii_alphanumeric() || "_-./+=%".contains(c)))
    {
        let token =
            word.trim_end_matches(|c: char| !(c.is_ascii_alphanumeric() || "_-./+=%".contains(c)));
        if token.len() >= 24
            || ["sk-", "eyJ", "ghp_", "gho_", "ghu_", "ghs_", "github_pat_"]
                .iter()
                .any(|p| token.starts_with(p))
        {
            safe.push_str(REDACTED);
            safe.push_str(&word[token.len()..]);
        } else {
            safe.push_str(word);
        }
    }
    bounded(safe)
}

fn bounded(mut text: String) -> String {
    let mut end = text.len().min(BODY_LIMIT);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    text
}

#[cfg(test)]
pub(crate) async fn mock_endpoint(body: String) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/token", listener.local_addr().unwrap());
    let app = axum::Router::new().route(
        "/token",
        axum::routing::post(move || async move { (http::StatusCode::BAD_REQUEST, body) }),
    );
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, task)
}

#[cfg(test)]
pub(crate) fn assert_failure_logs(error: &crate::tokens::TokenError) -> String {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        crate::logging::log_token_failure("fixture-request", "unavailable", error);
        crate::logging::log_token_failure("fixture-request", "refresh_failed", error);
        crate::logging::log_token_rotation_failed("1234567890", "fixture@example.test", error);
        crate::logging::log_account_state(
            "1234567890",
            Some("fixture@example.test"),
            "auth_error",
            &error.to_string(),
        );
    });
    let output = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    for secret in [
        "request-secret",
        "fixture-access",
        "fixture-refresh",
        "fixture-id",
        "fixture-code",
    ] {
        assert!(!output.contains(secret));
    }
    let events: Vec<Value> = output
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(events.len(), 4);
    for (event, name) in events.iter().zip([
        "token.unavailable",
        "token.refresh_failed",
        "token.rotation_failed",
        "account.auth_error",
    ]) {
        let fields = &event["fields"];
        assert_eq!(fields["message"], name);
        if name == "account.auth_error" {
            assert!(
                fields["detail"]
                    .as_str()
                    .unwrap()
                    .contains("The grant expired")
            );
        } else {
            assert_eq!(fields["status"], 400);
            assert_eq!(fields["oauth_error"], "invalid_grant");
            assert_eq!(
                fields["oauth_error_description"],
                "The grant expired; [REDACTED] was rejected."
            );
            assert!(fields["response_body"].as_str().unwrap().contains(REDACTED));
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    #[tokio::test]
    async fn token_error_response_fixture_is_logged_with_redacted_fields() {
        let body = json!({
            "error": "invalid_grant",
            "error_description": "The grant expired; request-secret was rejected.",
            "access_token": "fixture-access",
            "refresh_token": "fixture-refresh",
            "id_token": "fixture-id",
            "code": "fixture-code",
        })
        .to_string();
        let response = http::Response::builder().status(400).body(body).unwrap();
        let error = TokenEndpointError::from_response(response.into(), &["request-secret"]).await;
        let output = assert_failure_logs(&error.into());
        println!("{}", output.lines().next().unwrap());
    }

    #[test]
    fn keeps_oauth_prose_about_codes_and_refresh_tokens() {
        let description = "The authorization code or refresh token is invalid or has expired.";
        let body = json!({"error": "invalid_grant", "error_description": description}).to_string();
        let error = TokenEndpointError::from_body(400, body.as_bytes(), &[]);
        assert_eq!(error.error_description(), Some(description));
    }

    #[tokio::test]
    async fn unreadable_response_fixture_keeps_original_status() {
        let stream = futures::stream::once(async {
            Err::<String, _>(std::io::Error::other("fixture body failure"))
        });
        let response = http::Response::builder()
            .status(503)
            .body(reqwest::Body::wrap_stream(stream))
            .unwrap();
        let error = TokenEndpointError::from_response(response.into(), &[]).await;
        assert_eq!(error.status(), 503);
        assert_eq!(
            error.body_excerpt(),
            "[REDACTED: incomplete token endpoint response]"
        );
    }

    #[test]
    fn redacts_secrets_in_allowed_fields_and_nested_values() {
        for description in [
            "Grant rejected: short-code, short-access, short-id, short-refresh.",
            "Grant rejected: sk-fixture.",
            "Grant rejected: eyJfixture.payload.signature.",
            "Grant rejected: abcdefghijklmnopqrstuvwxyz0123456789.",
            "Grant rejected: access_token=short-access.",
            "Grant rejected: Bearer short-bearer",
            "Grant rejected: code: short-code",
            "Grant rejected: {\"id_token\":\"short-id\"}",
        ] {
            let body = json!({
                "error": "invalid_grant",
                "error_description": description,
                "nested": [{"access_token": "short-access", "id_token": "short-id", "refresh_token": "short-refresh", "code": "short-code"}],
            }).to_string();
            let error = TokenEndpointError::from_body(400, body.as_bytes(), &[]);
            assert_eq!(error.error(), Some("invalid_grant"));
            assert!(
                error
                    .error_description()
                    .unwrap()
                    .starts_with("Grant rejected:")
            );
            for secret in [
                "short-code",
                "short-access",
                "short-id",
                "short-refresh",
                "short-bearer",
                "sk-fixture",
                "eyJfixture",
                "abcdefghijklmnopqrstuvwxyz0123456789",
            ] {
                assert!(!error.to_string().contains(secret));
                assert!(!format!("{error:?}").contains(secret));
            }
        }
    }

    #[tokio::test]
    async fn non_json_malformed_and_oversized_response_fixtures_fail_closed() {
        for body in [
            "<html>access_token=fixture-hidden</html>".to_string(),
            "{\"error_description\":\"fixture-hidden".into(),
            json!({"error": "fixture-hidden".repeat(400)}).to_string(),
        ] {
            let response = http::Response::builder().status(400).body(body).unwrap();
            let error = TokenEndpointError::from_response(response.into(), &[]).await;
            assert_eq!(error.status(), 400);
            assert!(error.error().is_none());
            assert!(error.error_description().is_none());
            assert!(!error.to_string().contains("fixture-hidden"));
            assert!(error.body_excerpt().len() <= BODY_LIMIT);
        }
    }

    #[tokio::test]
    async fn stalled_body_keeps_status_and_times_out() {
        let stream = futures::stream::once(async {
            Ok::<_, std::io::Error>("{\"access_token\":\"fixture-hidden")
        })
        .chain(futures::stream::pending());
        let response = http::Response::builder()
            .status(400)
            .body(reqwest::Body::wrap_stream(stream))
            .unwrap();
        let error = tokio::time::timeout(
            Duration::from_secs(5),
            TokenEndpointError::from_response(response.into(), &[]),
        )
        .await
        .unwrap();
        assert_eq!(error.status(), 400);
        assert_eq!(
            error.body_excerpt(),
            "[REDACTED: incomplete token endpoint response]"
        );
    }
}
