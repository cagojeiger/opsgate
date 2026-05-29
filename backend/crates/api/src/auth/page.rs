use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};

pub fn html_page(status: StatusCode, title: &str, body: &str) -> Response {
    let escaped_title = escape_html(title);
    let escaped_body = escape_html(body);
    (
        status,
        Html(format!(
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>{escaped_title}</title></head><body><h1>{escaped_title}</h1><p>{escaped_body}</p></body></html>"
        )),
    )
        .into_response()
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
