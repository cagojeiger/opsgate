use super::*;

#[tokio::test]
async fn api_routes_require_bearer_before_handler() -> Result<(), Box<dyn std::error::Error>> {
    let app = crate::routes::app(state(ResolverMode::Registered(true))?);
    let response = app
        .oneshot(Request::builder().uri("/api/v1/me").body(Body::empty())?)
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let challenge = response
        .headers()
        .get(WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert!(challenge.starts_with("Bearer "));
    assert!(challenge.contains("resource_metadata="));
    assert!(!challenge.contains("scope="));
    Ok(())
}

#[tokio::test]
async fn api_routes_accept_valid_bearer() -> Result<(), Box<dyn std::error::Error>> {
    let app = crate::routes::app(state(ResolverMode::Registered(true))?);
    let valid = token(
        "sub-1",
        "https://auth.example.test",
        json!("https://api.example.test"),
        future_exp(),
        "kid-1",
    )?;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/me")
                .header("authorization", format!("Bearer {valid}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn api_routes_reject_invalid_bearer() -> Result<(), Box<dyn std::error::Error>> {
    let app = crate::routes::app(state(ResolverMode::Registered(true))?);
    let expired = token(
        "sub-1",
        "https://auth.example.test",
        json!("https://api.example.test"),
        epoch_secs().saturating_sub(3600),
        "kid-1",
    )?;
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/me")
                .header("authorization", format!("Bearer {expired}"))
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = response_json(response).await?;
    assert_eq!(body.get("error"), Some(&json!("invalid_token")));
    Ok(())
}

#[tokio::test]
async fn mcp_runtime_accepts_registered_user_before_protocol_handling()
-> Result<(), Box<dyn std::error::Error>> {
    let app = crate::routes::app(registered_state()?);
    let valid = token(
        "sub-1",
        "https://auth.example.test",
        json!("https://api.example.test"),
        future_exp(),
        "kid-1",
    )?;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header("authorization", format!("Bearer {valid}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))?,
        )
        .await?;

    assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
    assert_ne!(response.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn mcp_admin_accepts_registered_user_before_protocol_handling()
-> Result<(), Box<dyn std::error::Error>> {
    let app = crate::routes::app(registered_state()?);
    let valid = token(
        "sub-1",
        "https://auth.example.test",
        json!("https://api.example.test"),
        future_exp(),
        "kid-1",
    )?;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp/admin")
                .header("authorization", format!("Bearer {valid}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))?,
        )
        .await?;

    assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
    assert_ne!(response.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn unknown_api_routes_still_require_bearer() -> Result<(), Box<dyn std::error::Error>> {
    let app = crate::routes::app(state(ResolverMode::Registered(true))?);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/missing")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn authorization_server_metadata_route_returns_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    let response = request(
        state(ResolverMode::Registered(true))?,
        Request::builder()
            .uri("/.well-known/oauth-authorization-server")
            .body(Body::empty())?,
    )
    .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let value = response_json(response).await?;
    assert_eq!(
        value.get("issuer"),
        Some(&json!("https://auth.example.test"))
    );
    assert_eq!(
        value.get("authorization_endpoint"),
        Some(&json!("https://auth.example.test/authorize"))
    );
    assert_eq!(
        value.get("token_endpoint"),
        Some(&json!("https://auth.example.test/oauth/token"))
    );
    assert_eq!(
        value.get("revocation_endpoint"),
        Some(&json!("https://auth.example.test/oauth/revoke"))
    );
    assert_eq!(
        value.get("device_authorization_endpoint"),
        Some(&json!("https://auth.example.test/oauth/device/authorize"))
    );
    assert!(json_array_contains(
        &value,
        "grant_types_supported",
        "authorization_code"
    ));
    assert!(json_array_contains(
        &value,
        "grant_types_supported",
        "refresh_token"
    ));
    assert!(json_array_contains(
        &value,
        "grant_types_supported",
        "urn:ietf:params:oauth:grant-type:device_code"
    ));
    assert!(json_array_contains(
        &value,
        "code_challenge_methods_supported",
        "S256"
    ));
    assert!(json_array_contains(
        &value,
        "token_endpoint_auth_methods_supported",
        "none"
    ));
    assert!(json_array_contains(
        &value,
        "token_endpoint_auth_methods_supported",
        "client_secret_basic"
    ));
    assert!(json_array_contains(
        &value,
        "token_endpoint_auth_methods_supported",
        "client_secret_post"
    ));
    assert!(json_array_contains(&value, "scopes_supported", "openid"));
    assert!(json_array_contains(
        &value,
        "scopes_supported",
        "offline_access"
    ));
    assert_eq!(
        value.get("client_id_metadata_document_supported"),
        Some(&json!(true))
    );
    Ok(())
}

#[tokio::test]
async fn protected_resource_metadata_route_returns_root_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    let response = request(
        state_with_resource_url(ResolverMode::Registered(true), "https://api.example.test")?,
        Request::builder()
            .uri("/.well-known/oauth-protected-resource")
            .body(Body::empty())?,
    )
    .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let value = response_json(response).await?;
    assert_eq!(
        value.get("resource"),
        Some(&json!("https://api.example.test"))
    );
    assert!(json_array_contains(
        &value,
        "authorization_servers",
        "https://auth.example.test"
    ));
    assert!(json_array_contains(&value, "scopes_supported", "openid"));
    assert!(json_array_contains(
        &value,
        "scopes_supported",
        "offline_access"
    ));
    assert!(json_array_contains(
        &value,
        "bearer_methods_supported",
        "header"
    ));
    Ok(())
}

#[tokio::test]
async fn protected_resource_metadata_route_returns_path_qualified_metadata()
-> Result<(), Box<dyn std::error::Error>> {
    let state = state_with_resource_url(
        ResolverMode::Registered(true),
        "https://api.example.test/mcp",
    )?;

    let root_response = request(
        state.clone(),
        Request::builder()
            .uri("/.well-known/oauth-protected-resource")
            .body(Body::empty())?,
    )
    .await?;
    assert_eq!(root_response.status(), StatusCode::OK);
    let root_value = response_json(root_response).await?;
    assert_eq!(
        root_value.get("resource"),
        Some(&json!("https://api.example.test/mcp"))
    );

    for uri in [
        "/.well-known/oauth-protected-resource/mcp",
        "/.well-known/oauth-protected-resource/mcp/tools",
    ] {
        let response = request(
            state.clone(),
            Request::builder().uri(uri).body(Body::empty())?,
        )
        .await?;

        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        let value = response_json(response).await?;
        assert_eq!(
            value.get("resource"),
            Some(&json!("https://api.example.test/mcp"))
        );
    }
    Ok(())
}

#[tokio::test]
async fn mcp_unauthenticated_challenge_includes_resource_metadata_and_scope()
-> Result<(), Box<dyn std::error::Error>> {
    let state = state_with_resource_url(
        ResolverMode::Registered(true),
        "https://api.example.test/mcp",
    )?;

    for uri in ["/mcp", "/mcp/admin"] {
        let response = request(
            state.clone(),
            Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from("{}"))?,
        )
        .await?;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
        let challenge = response
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        assert!(challenge.starts_with("Bearer "));
        assert!(challenge.contains("resource_metadata="));
        assert!(challenge.contains("/.well-known/oauth-protected-resource/mcp"));
        assert!(challenge.contains("scope=\"openid offline_access\""));
    }
    Ok(())
}

#[tokio::test]
async fn rest_parity_routes_require_bearer() -> Result<(), Box<dyn std::error::Error>> {
    let app = crate::routes::app(registered_state()?);
    let cases = [
        (Method::POST, "/api/v1/api/call", "{}"),
        (Method::POST, "/api/v1/sql/query", "{}"),
        (Method::POST, "/api/v1/sql/schema", "{}"),
        (Method::GET, "/api/v1/mcp/connect", ""),
        (Method::GET, "/api/v1/summary", ""),
        (Method::GET, "/api/v1/activity", ""),
        (Method::GET, "/api/v1/audit/events", ""),
        (Method::GET, "/api/v1/history/api-calls", ""),
        (Method::GET, "/api/v1/history/sql-queries", ""),
        (Method::GET, "/api/v1/history/credentials", ""),
        (Method::POST, "/api/v1/credentials", "{}"),
        (Method::GET, "/api/v1/credentials", ""),
        (Method::DELETE, "/api/v1/credentials/prod-api", "{}"),
    ];

    for (method, uri, body) in cases {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method.clone())
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_owned()))?,
            )
            .await?;

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {uri}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn rest_parity_routes_return_validation_errors_instead_of_not_found()
-> Result<(), Box<dyn std::error::Error>> {
    let app = crate::routes::app(registered_state()?);

    let api_call = app
        .clone()
        .oneshot(authed_json_request(
            Method::POST,
            "/api/v1/api/call",
            r#"{"alias":"","purpose":"Inspect health response"}"#,
        )?)
        .await?;
    assert_eq!(api_call.status(), StatusCode::BAD_REQUEST);

    let sql_query = app
        .clone()
        .oneshot(authed_json_request(
            Method::POST,
            "/api/v1/sql/query",
            r#"{"alias":"","purpose":"Inspect rows safely"}"#,
        )?)
        .await?;
    assert_eq!(sql_query.status(), StatusCode::BAD_REQUEST);

    let sql_schema = app
        .clone()
        .oneshot(authed_json_request(
            Method::POST,
            "/api/v1/sql/schema",
            r#"{"alias":"","purpose":"Inspect schema safely"}"#,
        )?)
        .await?;
    assert_eq!(sql_schema.status(), StatusCode::BAD_REQUEST);

    let activity = app
        .clone()
        .oneshot(authed_json_request(
            Method::GET,
            "/api/v1/activity?limit=101",
            "",
        )?)
        .await?;
    assert_eq!(activity.status(), StatusCode::BAD_REQUEST);

    let list = app
        .oneshot(authed_json_request(
            Method::GET,
            "/api/v1/credentials?limit=101",
            "",
        )?)
        .await?;
    assert_eq!(list.status(), StatusCode::BAD_REQUEST);

    let app = crate::routes::app(registered_state()?);
    let register = app
        .clone()
        .oneshot(authed_json_request(
            Method::POST,
            "/api/v1/credentials",
            r#"{"category":"not-a-category"}"#,
        )?)
        .await?;
    assert_eq!(register.status(), StatusCode::BAD_REQUEST);

    let delete = app
        .oneshot(authed_json_request(
            Method::DELETE,
            "/api/v1/credentials/bad%20alias",
            r#"{"reason":"Retire stale credential"}"#,
        )?)
        .await?;
    assert_eq!(delete.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn rest_parity_post_routes_do_not_require_content_type_header()
-> Result<(), Box<dyn std::error::Error>> {
    let app = crate::routes::app(registered_state()?);
    let valid = valid_api_token()?;
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/api/call")
                .header("authorization", format!("Bearer {valid}"))
                .body(Body::from(
                    r#"{"alias":"","purpose":"Inspect health response"}"#,
                ))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn openapi_routes_are_disabled_by_default() -> Result<(), Box<dyn std::error::Error>> {
    let app = crate::routes::app(registered_state()?);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn openapi_routes_can_be_enabled() -> Result<(), Box<dyn std::error::Error>> {
    let mut state = registered_state()?;
    Arc::make_mut(&mut state.config).openapi_enabled = true;
    let response = request(
        state,
        Request::builder()
            .uri("/openapi.json")
            .body(Body::empty())?,
    )
    .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let value = response_json(response).await?;
    assert_eq!(value.get("openapi"), Some(&json!("3.1.0")));
    Ok(())
}

#[tokio::test]
async fn public_routes_do_not_require_bearer() -> Result<(), Box<dyn std::error::Error>> {
    let app = crate::routes::app(state(ResolverMode::Registered(true))?);
    let response = app
        .oneshot(Request::builder().uri("/health").body(Body::empty())?)
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}
