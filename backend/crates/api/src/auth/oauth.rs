use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::http::header::USER_AGENT;
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
    let remote_ip = remote_ip(&headers);
    let user_agent = user_agent(&headers);
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
            let caller = caller.with_request_metadata(None, remote_ip, user_agent);
            audit_signup(&state, Some(&caller), "ok", None, &attrs).await;
            let body = format!(
                "You're registered, sub={}. Reconnect your MCP client to {}.",
                attrs.sub, state.config.resource_url
            );
            (jar, html_page(StatusCode::OK, "Login complete", &body)).into_response()
        }
        Err(IdentityError::NotAdmin) => {
            audit_signup(&state, None, "denied", Some("not_admin"), &attrs).await;
            (
                jar,
                html_page(StatusCode::FORBIDDEN, "Login forbidden", "not allowed"),
            )
                .into_response()
        }
        Err(IdentityError::Inactive) => (
            jar,
            html_page(StatusCode::FORBIDDEN, "Login forbidden", "user is inactive"),
        )
            .into_response(),
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

fn remote_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

async fn audit_signup(
    state: &AppState,
    caller: Option<&opsgate_domain::Caller>,
    outcome: &str,
    denial_reason: Option<&str>,
    attrs: &ResolveAttrs,
) {
    let mut detail = serde_json::Map::new();
    detail.insert("schema_version".to_owned(), serde_json::json!(1));
    detail.insert("sub".to_owned(), serde_json::json!(attrs.sub.clone()));
    detail.insert("email".to_owned(), serde_json::json!(attrs.email.clone()));
    if let Some(reason) = denial_reason {
        detail.insert("denial_reason".to_owned(), serde_json::json!(reason));
    }
    let params = opsgate_db::AuditLogParams {
        action: "browser.signup".to_owned(),
        channel: "browser".to_owned(),
        outcome: outcome.to_owned(),
        severity: if outcome == "ok" { "info" } else { "warning" }.to_owned(),
        actor_user_id: caller.map(|caller| caller.user.id),
        actor_role: caller.map(|caller| caller.role.as_str().to_owned()),
        actor_ip: caller.and_then(|caller| caller.remote_ip.clone()),
        actor_user_agent: caller.and_then(|caller| caller.user_agent.clone()),
        target_type: Some("identity".to_owned()),
        target_id: caller.map(|caller| caller.user.id.to_string()),
        target_key: Some(attrs.sub.clone()),
        request_id: None,
        purpose: None,
        detail: serde_json::Value::Object(detail),
    };
    if let Err(error) = state.audit.append(params).await {
        tracing::error!(event = "browser.signup.audit_failed", detail = %error);
    }
}
