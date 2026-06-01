use super::*;

#[tokio::test]
async fn verify_accepts_valid_token() -> Result<(), Box<dyn std::error::Error>> {
    let jwt = jwt_authority("https://api.example.test")?;
    let token = token(
        "sub-1",
        "https://auth.example.test",
        json!("https://api.example.test"),
        future_exp(),
        "kid-1",
    )?;
    let attrs = jwt.verify(&token).await?;
    assert_eq!(attrs.sub, "sub-1");
    Ok(())
}

#[tokio::test]
async fn verify_rejects_invalid_claims_without_panic() -> Result<(), Box<dyn std::error::Error>> {
    let jwt = jwt_authority("https://api.example.test")?;
    let cases = [
        token(
            "sub-1",
            "https://auth.example.test",
            json!("https://api.example.test"),
            epoch_secs().saturating_sub(3600),
            "kid-1",
        )?,
        token(
            "sub-1",
            "https://other.example.test",
            json!("https://api.example.test"),
            future_exp(),
            "kid-1",
        )?,
        token(
            "sub-1",
            "https://auth.example.test",
            json!("https://other.example.test"),
            future_exp(),
            "kid-1",
        )?,
        token(
            "sub-1",
            "https://auth.example.test",
            json!("https://api.example.test"),
            future_exp(),
            "unknown",
        )?,
        "not-a-jwt".to_owned(),
        alg_none_token(),
    ];
    for (idx, candidate) in cases.into_iter().enumerate() {
        let err = jwt.verify(&candidate).await.err();
        assert!(
            matches!(err, Some(AuthError::InvalidToken)),
            "case {idx}: {err:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn verify_accepts_aud_array_and_trailing_slash() -> Result<(), Box<dyn std::error::Error>> {
    let jwt = jwt_authority("https://api.example.test")?;
    let token = token(
        "sub-1",
        "https://auth.example.test",
        json!(["other", "https://api.example.test/"]),
        future_exp(),
        "kid-1",
    )?;
    let attrs = jwt.verify(&token).await?;
    assert_eq!(attrs.sub, "sub-1");
    Ok(())
}

#[tokio::test]
async fn verify_maps_registered_state_errors() -> Result<(), Box<dyn std::error::Error>> {
    let missing = TestResolver {
        mode: ResolverMode::Missing,
    };
    let missing_err = resolve_api_caller(&missing, attrs()).await.err();
    assert!(matches!(missing_err, Some(AuthError::NotRegistered)));

    let inactive = TestResolver {
        mode: ResolverMode::Registered(false),
    };
    let inactive_err = resolve_api_caller(&inactive, attrs()).await.err();
    assert!(matches!(inactive_err, Some(AuthError::Inactive)));
    Ok(())
}
