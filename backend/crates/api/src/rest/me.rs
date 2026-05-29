use axum::extract::Extension;
use axum::routing::get;
use axum::{Json, Router};
use opsgate_domain::Caller;

use crate::identity::me::{MeOutput, build_me};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/v1/me", get(get_me))
}

async fn get_me(Extension(caller): Extension<Caller>) -> Json<MeOutput> {
    Json(build_me(&caller))
}
