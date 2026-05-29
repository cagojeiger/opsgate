use axum::Json;
use axum::extract::Extension;
use opsgate_domain::Caller;

use crate::identity::me::{MeOutput, build_me};

pub async fn me(Extension(caller): Extension<Caller>) -> Json<MeOutput> {
    Json(build_me(&caller))
}
