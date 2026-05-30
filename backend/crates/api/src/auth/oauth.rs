use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::CookieJar;
use opsgate_domain::{IdentityError, ResolveAttrs};
use serde::Deserialize;
use subtle::ConstantTimeEq;

use crate::auth::oauth_exchange::exchange_code_for_userinfo;
use crate::auth::oauth_flow::{
    LOGIN_NONCE_COOKIE, LOGIN_STATE_COOKIE, LOGIN_VERIFIER_COOKIE, clear_flow_cookies, flow_cookie,
    new_login_flow,
};
use crate::auth::page::html_page;
use crate::request_context::RequestMetadata;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

pub async fn login(State(state): State<AppState>, jar: CookieJar) -> Response {
    let login_flow = match new_login_flow(&state.oidc).await {
        Ok(flow) => flow,
        Err(error) => {
            tracing::error!(event = "oauth.login_flow_failed", %error);
            return html_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Login failed",
                "internal error",
            );
        }
    };
    let jar = jar
        .add(flow_cookie(
            LOGIN_STATE_COOKIE,
            login_flow.csrf_state,
            state.config.secure_cookies,
        ))
        .add(flow_cookie(
            LOGIN_VERIFIER_COOKIE,
            login_flow.pkce_verifier,
            state.config.secure_cookies,
        ))
        .add(flow_cookie(
            LOGIN_NONCE_COOKIE,
            login_flow.nonce,
            state.config.secure_cookies,
        ));
    (jar, Redirect::temporary(&login_flow.redirect_url)).into_response()
}

pub async fn callback(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let metadata = RequestMetadata::from_headers(&headers);
    let cookie_state = jar
        .get(LOGIN_STATE_COOKIE)
        .map(|cookie| cookie.value().to_owned());
    let cookie_verifier = jar
        .get(LOGIN_VERIFIER_COOKIE)
        .map(|cookie| cookie.value().to_owned());
    let cookie_nonce = jar
        .get(LOGIN_NONCE_COOKIE)
        .map(|cookie| cookie.value().to_owned());
    let jar = clear_flow_cookies(jar, state.config.secure_cookies);

    if query.error.is_some() {
        return (
            jar,
            html_page(
                StatusCode::BAD_REQUEST,
                "Login error",
                "authorization failed",
            ),
        )
            .into_response();
    }

    let (Some(code), Some(query_state)) = (query.code.as_deref(), query.state.as_deref()) else {
        return (
            jar,
            html_page(
                StatusCode::BAD_REQUEST,
                "Login error",
                "missing code or state",
            ),
        )
            .into_response();
    };

    let Some(cookie_state) = cookie_state else {
        return (
            jar,
            html_page(StatusCode::BAD_REQUEST, "Login error", "state mismatch"),
        )
            .into_response();
    };
    if cookie_state
        .as_bytes()
        .ct_eq(query_state.as_bytes())
        .unwrap_u8()
        != 1
    {
        return (
            jar,
            html_page(StatusCode::BAD_REQUEST, "Login error", "state mismatch"),
        )
            .into_response();
    }

    let Some(verifier) = cookie_verifier.filter(|value| !value.is_empty()) else {
        return (
            jar,
            html_page(StatusCode::BAD_REQUEST, "Login error", "missing verifier"),
        )
            .into_response();
    };
    let Some(nonce) = cookie_nonce.filter(|value| !value.is_empty()) else {
        return (
            jar,
            html_page(StatusCode::BAD_REQUEST, "Login error", "missing nonce"),
        )
            .into_response();
    };

    let userinfo =
        match exchange_code_for_userinfo(&state.oidc, &state.http, code, &verifier, &nonce).await {
            Ok(userinfo) => userinfo,
            Err(error) => {
                tracing::warn!(event = "oauth.exchange_failed", %error);
                return (
                    jar,
                    html_page(
                        StatusCode::BAD_GATEWAY,
                        "Login error",
                        "authorization exchange failed",
                    ),
                )
                    .into_response();
            }
        };
    let attrs = ResolveAttrs {
        sub: userinfo.sub,
        email: userinfo.email.unwrap_or_default(),
        name: userinfo.name.unwrap_or_default(),
    };
    match state.resolver.resolve_browser(attrs.clone()).await {
        Ok(caller) => {
            let caller = caller.with_request_metadata(
                metadata.request_id.clone(),
                metadata.remote_ip.clone(),
                metadata.user_agent.clone(),
            );
            crate::audit::auth::record_signup(
                &state.audit,
                Some(&caller),
                crate::audit::AuditOutcome::Ok,
                None,
                &attrs,
                &metadata,
            )
            .await;
            let body = format!(
                "You're registered, sub={}. Reconnect your MCP client to {}.",
                attrs.sub, state.config.resource_url
            );
            (jar, html_page(StatusCode::OK, "Login complete", &body)).into_response()
        }
        Err(IdentityError::Inactive) => {
            crate::audit::auth::record_signup(
                &state.audit,
                None,
                crate::audit::AuditOutcome::Denied,
                Some("inactive_user"),
                &attrs,
                &metadata,
            )
            .await;
            (
                jar,
                html_page(StatusCode::FORBIDDEN, "Login forbidden", "user is inactive"),
            )
                .into_response()
        }
        Err(error) => {
            tracing::error!(event = "oauth.resolve_failed", %error);
            (
                jar,
                html_page(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Login error",
                    "internal error",
                ),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use opsgate_domain::{Caller, Channel, User};
    use uuid::Uuid;

    use super::*;

    fn attrs() -> ResolveAttrs {
        ResolveAttrs {
            sub: "sub-1".to_owned(),
            email: "user@example.test".to_owned(),
            name: "User".to_owned(),
        }
    }

    fn metadata() -> RequestMetadata {
        RequestMetadata {
            request_id: Some("req-browser".to_owned()),
            remote_ip: Some("203.0.113.12".to_owned()),
            user_agent: Some("opsgate-test".to_owned()),
        }
    }

    #[test]
    fn signup_denial_audit_row_records_identity_and_request_metadata() {
        let params = crate::audit::auth::signup_event(
            None,
            crate::audit::AuditOutcome::Denied,
            Some("not_allowed"),
            &attrs(),
            &metadata(),
        )
        .into_params();

        assert_eq!(params.action, "browser.signup");
        assert_eq!(params.outcome, "denied");
        assert_eq!(params.actor_user_id, None);
        assert_eq!(params.request_id.as_deref(), Some("req-browser"));
        assert_eq!(params.actor_ip.as_deref(), Some("203.0.113.12"));
        assert_eq!(params.actor_user_agent.as_deref(), Some("opsgate-test"));
        assert_eq!(
            params.detail.get("denial_reason"),
            Some(&serde_json::json!("not_allowed"))
        );
        let serialized = params.detail.to_string();
        assert!(!serialized.contains("token"));
        assert!(!serialized.contains("secret"));
    }

    #[test]
    fn signup_success_audit_row_uses_caller_metadata() {
        let now = Utc::now();
        let caller = Caller {
            user: User {
                id: Uuid::nil(),
                sub: "sub-1".to_owned(),
                email: "admin@example.test".to_owned(),
                display_name: "Admin".to_owned(),
                is_active: true,
                created_at: now,
                updated_at: now,
            },
            channel: Channel::Browser,
            request_id: Some("req-caller".to_owned()),
            remote_ip: Some("198.51.100.8".to_owned()),
            user_agent: Some("caller-agent".to_owned()),
        };

        let params = crate::audit::auth::signup_event(
            Some(&caller),
            crate::audit::AuditOutcome::Ok,
            None,
            &attrs(),
            &metadata(),
        )
        .into_params();

        assert_eq!(params.outcome, "ok");
        assert_eq!(params.actor_user_id, Some(Uuid::nil()));
        assert_eq!(params.request_id.as_deref(), Some("req-caller"));
        assert_eq!(params.actor_ip.as_deref(), Some("198.51.100.8"));
        assert_eq!(params.actor_user_agent.as_deref(), Some("caller-agent"));
    }
}
