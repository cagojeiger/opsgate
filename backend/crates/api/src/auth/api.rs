use std::time::Instant;

use axum::body::Body;
use axum::extract::{MatchedPath, State};
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use opsgate_model::{Caller, IdentityError, ResolveAttrs};

use crate::auth::bearer::{AuthError, auth_error_response, extract_bearer};
use crate::identity::CallerResolver;
use crate::request_context::RequestMetadata;
use crate::state::AuthRuntimeState;

pub async fn require_api_bearer(
    State(state): State<AuthRuntimeState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let metadata = RequestMetadata::from_headers(request.headers());
    let Some(token) = extract_bearer(request.headers()).map(str::to_owned) else {
        return auth_error_response(&state.config, AuthError::MissingToken);
    };

    let caller =
        match verify_api_bearer(&state.auth.jwt, state.auth.resolver.as_ref(), &token).await {
            Ok(caller) => caller.with_request_metadata(
                metadata.request_id.clone(),
                metadata.remote_ip.clone(),
                metadata.user_agent.clone(),
            ),
            Err(error) => {
                crate::audit::auth::record_auth_denied(
                    &state.audit,
                    opsgate_model::Channel::Api,
                    &metadata,
                    &error,
                )
                .await;
                return auth_error_response(&state.config, error);
            }
        };

    let method = request.method().clone();
    let uri = request.uri().clone();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str)
        .unwrap_or("")
        .to_owned();
    let started = Instant::now();
    let audit_caller = caller.clone();
    request.extensions_mut().insert(caller);
    let response = next.run(request).await;
    let status = response.status().as_u16();
    crate::audit::request::record_api_request(
        &state.audit,
        &audit_caller,
        &method,
        uri.path(),
        &route,
        status,
        started,
    )
    .await;
    response
}

pub(crate) async fn verify_api_bearer(
    jwt: &crate::auth::jwt::JwtAuthority,
    resolver: &dyn CallerResolver,
    token: &str,
) -> Result<Caller, AuthError> {
    let attrs = jwt.verify(token).await?;
    resolve_api_caller(resolver, attrs).await
}

pub(crate) async fn resolve_api_caller(
    resolver: &dyn CallerResolver,
    attrs: ResolveAttrs,
) -> Result<Caller, AuthError> {
    resolver
        .resolve_api(attrs)
        .await
        .map_err(map_identity_error)
}

fn map_identity_error(error: IdentityError) -> AuthError {
    match error {
        IdentityError::NotRegistered => AuthError::NotRegistered,
        IdentityError::Inactive => AuthError::Inactive,
        IdentityError::Store(_error) => AuthError::Internal,
    }
}
