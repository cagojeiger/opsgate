pub(crate) fn message(value: &str) -> String {
    value.replace(['\r', '\n'], " ").chars().take(512).collect()
}
