pub fn database_url(name: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(Some(value)),
        _ if std::env::var("CI").is_ok_and(|value| value == "true") => {
            Err(format!("{name} must be set for PostgreSQL integration tests in CI").into())
        }
        _ => {
            eprintln!("skipping PostgreSQL integration tests; set {name} to run them");
            Ok(None)
        }
    }
}
