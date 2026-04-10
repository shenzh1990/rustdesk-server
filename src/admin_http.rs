use crate::{peer::PeerMap, rendezvous_server::list_punch_req_audits};
use axum::{
    extract::{Extension, Path, Query},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect},
    routing::{delete, get, post, put},
    Json, Router,
};
use hbb_common::log;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde_derive::{Deserialize, Serialize};
use std::{collections::{HashMap, HashSet}, sync::Arc};
use tower_http::cors::CorsLayer;

#[derive(Clone)]
pub(crate) struct AppState {
    pm: PeerMap,
    jwt_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Claims {
    sub: i64,
    username: String,
    role: String,
    exp: usize,
}

#[derive(Debug, Serialize)]
struct ApiError {
    message: String,
}

#[derive(Debug, Deserialize)]
struct LoginReq {
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct LoginResp {
    token: String,
    role: String,
    username: String,
    user_id: i64,
}

#[derive(Debug, Deserialize)]
struct CreateUserReq {
    username: String,
    password: String,
    role: Option<String>,
}

#[derive(Debug, Serialize)]
struct UserDto {
    id: i64,
    username: String,
    role: String,
    status: i64,
    created_at: String,
}

#[derive(Debug, Serialize)]
struct CurrentUserResp {
    id: i64,
    username: String,
    role: String,
    is_admin: bool,
}

#[derive(Debug, Serialize)]
struct ClientDto {
    id: String,
    name: Option<String>,
    created_at: String,
    status: Option<i64>,
    is_controlled: bool,
    note: Option<String>,
    online: bool,
    last_seen_secs: Option<u64>,
    ip: String,
}

#[derive(Debug, Deserialize)]
struct AuditQuery {
    offset: Option<usize>,
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct AuditDto {
    timestamp: String,
    from_ip: String,
    to_ip: String,
    to_id: String,
}

#[derive(Debug, Serialize)]
struct GroupDto {
    id: i64,
    name: String,
    created_at: String,
}

#[derive(Debug, Deserialize)]
struct CreateGroupReq {
    name: String,
}

#[derive(Debug, Deserialize, Default)]
struct CompatLoginReq {
    username: Option<String>,
    password: Option<String>,
    id: Option<String>,
    uuid: Option<String>,
    #[serde(rename = "type")]
    req_type: Option<String>,
    #[serde(rename = "verificationCode")]
    verification_code: Option<String>,
    #[serde(rename = "tfaCode")]
    tfa_code: Option<String>,
    secret: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct PagingQuery {
    current: Option<usize>,
    #[serde(rename = "pageSize")]
    page_size: Option<usize>,
    status: Option<String>,
    accessible: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct AbPeersQuery {
    ab: Option<String>,
    current: Option<usize>,
    #[serde(rename = "pageSize")]
    page_size: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct AbTagAddReq {
    name: String,
    color: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct AbTagRenameReq {
    old: String,
    new: String,
}

#[derive(Debug, Deserialize)]
struct AbTagUpdateReq {
    name: String,
    color: i64,
}

#[derive(Debug, Deserialize)]
struct AuditUpdateReq {
    guid: Option<String>,
    note: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdatePeerNameReq {
    name: Option<String>,
}

pub(crate) fn spawn_admin_http(pm: PeerMap, api_port: i32) {
    if api_port <= 0 || api_port > u16::MAX as i32 {
        log::error!("Invalid API port: {}", api_port);
        return;
    }
    let jwt_secret =
        std::env::var("ADMIN_JWT_SECRET").unwrap_or_else(|_| "change-this-secret".to_owned());
    let state = Arc::new(AppState { pm, jwt_secret });
    let app = Router::new()
        .route("/", get(index_redirect))
        .route("/admin", get(admin_redirect))
        .route("/admin/login", get(admin_login_page))
        .route("/admin/dashboard", get(admin_dashboard_page))
        .route("/admin/style.css", get(admin_style_css))
        .route("/admin/login.js", get(admin_login_js))
        .route("/admin/dashboard.js", get(admin_dashboard_js))
        .route("/api/health", get(health))
        .route("/api/login", post(compat_login))
        .route("/api/admin/login", post(login))
        .route("/api/currentUser", get(current_user).post(current_user_post))
        .route("/api/logout", post(logout))
        .route("/api/login-options", get(login_options))
        .route("/api/ab/settings", post(ab_settings))
        .route("/api/ab/personal", post(ab_personal))
        .route("/api/ab/shared/profiles", post(ab_shared_profiles))
        .route("/api/ab/peers", post(ab_peers))
        .route("/api/ab/tags/:guid", post(ab_tags))
        .route("/api/ab/peer/add/:guid", post(ab_peer_add))
        .route("/api/ab/peer/update/:guid", put(ab_peer_update))
        .route("/api/ab/peer/:guid", delete(ab_peer_delete))
        .route("/api/ab/tag/add/:guid", post(ab_tag_add))
        .route("/api/ab/tag/rename/:guid", put(ab_tag_rename))
        .route("/api/ab/tag/update/:guid", put(ab_tag_update))
        .route("/api/ab/tag/:guid", delete(ab_tag_delete))
        .route("/api/audit", put(update_audit_note))
        .route("/api/users", get(users_dispatch).post(create_user))
        .route("/api/users/:user_id", delete(delete_user))
        .route("/api/users/:user_id/enable", post(enable_user))
        .route("/api/users/:user_id/disable", post(disable_user))
        .route("/api/peers", get(peers_dispatch))
        .route("/api/peers/:peer_id", delete(delete_peer))
        .route("/api/peers/:peer_id/enable", post(enable_peer))
        .route("/api/peers/:peer_id/disable", post(disable_peer))
        .route("/api/peers/:peer_id/name", put(update_peer_name))
        .route("/api/peers/:peer_id/mark-controlled", post(mark_controlled_peer))
        .route("/api/peers/:peer_id/unmark-controlled", post(unmark_controlled_peer))
        .route("/api/tree/groups", get(group_tree))
        .route("/api/tree/users", get(user_tree))
        .route("/api/users/:user_id/peers", get(list_user_peers))
        .route(
            "/api/users/:user_id/peers/:peer_id",
            post(grant_user_peer).delete(revoke_user_peer),
        )
        .route("/api/users/:user_id/groups", get(list_user_groups))
        .route(
            "/api/users/:user_id/groups/:group_id",
            post(grant_user_group).delete(revoke_user_group),
        )
        .route("/api/groups", get(list_groups).post(create_group))
        .route("/api/groups/:group_id", delete(delete_group))
        .route("/api/groups/:group_id/peers", get(list_group_peers))
        .route("/api/device-group/accessible", get(device_group_accessible))
        .route(
            "/api/groups/:group_id/peers/:peer_id",
            post(add_group_peer).delete(remove_group_peer),
        )
        .route("/api/audits/conn", get(list_conn_audits))
        // Compatibility routes for older API paths used in this repo
        .route("/api/admin/users", get(list_users).post(create_user))
        .route("/api/admin/clients", get(list_clients))
        .route(
            "/api/admin/users/:user_id/clients",
            get(list_user_peers),
        )
        .route(
            "/api/admin/users/:user_id/clients/:peer_id",
            post(grant_user_peer).delete(revoke_user_peer),
        )
        .layer(Extension(state))
        .layer(CorsLayer::permissive());
    hbb_common::tokio::spawn(async move {
        let addr = std::net::SocketAddr::from(([0, 0, 0, 0], api_port as u16));
        log::info!("Admin API listening on http://{}", addr);
        if let Err(err) = axum::Server::bind(&addr)
            .serve(app.into_make_service())
            .await
        {
            log::error!("Admin API stopped: {}", err);
        }
    });
}

async fn index_redirect() -> Redirect {
    Redirect::to("/admin/login")
}

async fn admin_redirect() -> Redirect {
    Redirect::to("/admin/login")
}

async fn admin_login_page() -> Html<&'static str> {
    Html(ADMIN_LOGIN_HTML)
}

async fn admin_dashboard_page() -> Html<&'static str> {
    Html(ADMIN_DASHBOARD_HTML)
}

async fn admin_style_css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        ADMIN_STYLE_CSS,
    )
}

async fn admin_login_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/javascript; charset=utf-8")],
        ADMIN_LOGIN_JS,
    )
}

async fn admin_dashboard_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/javascript; charset=utf-8")],
        ADMIN_DASHBOARD_JS,
    )
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true }))
}

async fn ensure_ab_profile_for_claims(
    state: &Arc<AppState>,
    claims: &Claims,
    guid: Option<&str>,
) -> Result<crate::database::AbProfileRecord, (StatusCode, Json<ApiError>)> {
    if let Some(guid) = guid {
        let profile = state
            .pm
            .db
            .get_ab_profile(guid)
            .await
            .map_err(internal_err)?;
        if let Some(p) = profile {
            if claims.role == "admin" || p.owner_user_id == claims.sub {
                return Ok(p);
            }
            return Err(auth_err("Permission denied"));
        }
    }
    let user = state
        .pm
        .db
        .get_user_by_id(claims.sub)
        .await
        .map_err(internal_err)?
        .ok_or_else(|| auth_err("Invalid user"))?;
    state
        .pm
        .db
        .ensure_personal_ab(user.id, &user.username)
        .await
        .map_err(internal_err)
}

async fn ab_settings(
    Extension(_state): Extension<Arc<AppState>>,
    _headers: HeaderMap,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "max_peer_one_ab": 1000 }))
}

async fn ab_personal(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    let p = ensure_ab_profile_for_claims(&state, &claims, None).await?;
    Ok(Json(serde_json::json!({ "guid": p.guid })))
}

async fn ab_shared_profiles(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<PagingQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    let rows = state
        .pm
        .db
        .list_shared_ab_profiles(claims.sub)
        .await
        .map_err(internal_err)?;
    let current = q.current.unwrap_or(1).max(1);
    let page_size = q.page_size.unwrap_or(100).clamp(1, 500);
    let start = (current - 1) * page_size;
    let data: Vec<serde_json::Value> = rows
        .iter()
        .skip(start)
        .take(page_size)
        .map(|r| {
            serde_json::json!({
                "guid": r.guid,
                "name": r.name,
                "owner": claims.username,
                "note": r.note.clone().unwrap_or_default(),
                "info": {},
                "rule": r.rule,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "total": rows.len(), "data": data })))
}

async fn ab_peers(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<AbPeersQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    let profile = ensure_ab_profile_for_claims(&state, &claims, q.ab.as_deref()).await?;
    let rows = state
        .pm
        .db
        .list_ab_peers(&profile.guid)
        .await
        .map_err(internal_err)?;
    let current = q.current.unwrap_or(1).max(1);
    let page_size = q.page_size.unwrap_or(100).clamp(1, 500);
    let start = (current - 1) * page_size;
    let data: Vec<serde_json::Value> = rows
        .iter()
        .skip(start)
        .take(page_size)
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "hash": r.hash,
                "password": r.password,
                "username": r.username,
                "hostname": r.hostname,
                "platform": r.platform,
                "alias": r.alias,
                "tags": r.tags,
                "note": r.note,
                "same_server": r.same_server,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "total": rows.len(), "data": data })))
}

async fn ab_tags(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path(guid): Path<String>,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    let profile = ensure_ab_profile_for_claims(&state, &claims, Some(&guid)).await?;
    let rows = state
        .pm
        .db
        .list_ab_tags(&profile.guid)
        .await
        .map_err(internal_err)?;
    Ok(Json(
        rows.into_iter()
            .map(|t| serde_json::json!({ "name": t.name, "color": t.color }))
            .collect(),
    ))
}

async fn ab_peer_add(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    let profile = ensure_ab_profile_for_claims(&state, &claims, Some(&guid)).await?;
    state
        .pm
        .db
        .add_ab_peer(&profile.guid, &body)
        .await
        .map_err(internal_err)?;
    Ok(StatusCode::OK)
}

async fn ab_peer_update(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    let profile = ensure_ab_profile_for_claims(&state, &claims, Some(&guid)).await?;
    state
        .pm
        .db
        .update_ab_peer_partial(&profile.guid, &body)
        .await
        .map_err(internal_err)?;
    Ok(StatusCode::OK)
}

async fn ab_peer_delete(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    Json(ids): Json<Vec<String>>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    let profile = ensure_ab_profile_for_claims(&state, &claims, Some(&guid)).await?;
    state
        .pm
        .db
        .delete_ab_peers(&profile.guid, &ids)
        .await
        .map_err(internal_err)?;
    Ok(StatusCode::OK)
}

async fn ab_tag_add(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    Json(req): Json<AbTagAddReq>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    let profile = ensure_ab_profile_for_claims(&state, &claims, Some(&guid)).await?;
    state
        .pm
        .db
        .add_ab_tag(&profile.guid, req.name.trim(), req.color.unwrap_or(0))
        .await
        .map_err(internal_err)?;
    Ok(StatusCode::OK)
}

async fn ab_tag_rename(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    Json(req): Json<AbTagRenameReq>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    let profile = ensure_ab_profile_for_claims(&state, &claims, Some(&guid)).await?;
    state
        .pm
        .db
        .rename_ab_tag(&profile.guid, req.old.trim(), req.new.trim())
        .await
        .map_err(internal_err)?;
    Ok(StatusCode::OK)
}

async fn ab_tag_update(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    Json(req): Json<AbTagUpdateReq>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    let profile = ensure_ab_profile_for_claims(&state, &claims, Some(&guid)).await?;
    state
        .pm
        .db
        .update_ab_tag_color(&profile.guid, req.name.trim(), req.color)
        .await
        .map_err(internal_err)?;
    Ok(StatusCode::OK)
}

async fn ab_tag_delete(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    Json(tags): Json<Vec<String>>,
) -> Result<StatusCode, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    let profile = ensure_ab_profile_for_claims(&state, &claims, Some(&guid)).await?;
    state
        .pm
        .db
        .delete_ab_tags(&profile.guid, &tags)
        .await
        .map_err(internal_err)?;
    Ok(StatusCode::OK)
}

async fn update_audit_note(
    Json(_req): Json<AuditUpdateReq>,
) -> StatusCode {
    StatusCode::OK
}
async fn login_options() -> Json<Vec<String>> {
    Json(vec![])
}

fn compat_user_payload(username: &str, role: &str, status: i64) -> serde_json::Value {
    serde_json::json!({
        "name": username,
        "display_name": username,
        "avatar": "",
        "email": "",
        "note": "",
        "status": status,
        "is_admin": role == "admin",
        "verifier": "",
        "info": {
            "email_verification": false,
            "email_alarm_notification": false,
            "login_device_whitelist": [],
            "other": {}
        }
    })
}

async fn compat_login(
    Extension(state): Extension<Arc<AppState>>,
    Json(req): Json<CompatLoginReq>,
) -> Json<serde_json::Value> {
    let req_type = req.req_type.unwrap_or_else(|| "account".to_owned());
    let username = req.username.unwrap_or_default();
    let password = req.password.unwrap_or_default();
    let peer_id = req.id.unwrap_or_default();

    if !username.trim().is_empty() || !password.is_empty() {
        if req_type != "account" && req_type != "mobile" {
            return Json(serde_json::json!({ "error": "Unsupported login type" }));
        }
        if username.trim().is_empty() || password.is_empty() {
            return Json(serde_json::json!({ "error": "Invalid username or password" }));
        }
        let user = match state.pm.db.get_user_by_name(username.trim()).await {
            Ok(Some(v)) => v,
            _ => return Json(serde_json::json!({ "error": "Invalid username or password" })),
        };
        if user.status == 0 {
            return Json(serde_json::json!({ "error": "User is disabled" }));
        }
        if !bcrypt::verify(password, &user.password_hash).unwrap_or(false) {
            return Json(serde_json::json!({ "error": "Invalid username or password" }));
        }
        let claims = Claims {
            sub: user.id,
            username: user.username.clone(),
            role: user.role.clone(),
            exp: (chrono::Utc::now().timestamp() + 12 * 3600) as usize,
        };
        let token = match encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
        ) {
            Ok(v) => v,
            Err(err) => return Json(serde_json::json!({ "error": err.to_string() })),
        };
        return Json(serde_json::json!({
            "type": "access_token",
            "access_token": token,
            "user": compat_user_payload(&user.username, &user.role, user.status)
        }));
    }

    if peer_id.trim().is_empty() {
        return Json(serde_json::json!({ "error": "Invalid username or password" }));
    }

    let peer = match state.pm.db.get_peer_record(peer_id.trim()).await {
        Ok(Some(v)) => v,
        Ok(None) => return Json(serde_json::json!({ "error": "Device not found" })),
        Err(err) => return Json(serde_json::json!({ "error": err.to_string() })),
    };
    if peer.status.unwrap_or(1) == 0 {
        return Json(serde_json::json!({ "error": "Device is disabled" }));
    }
    if peer.is_controlled == 0 {
        return Json(serde_json::json!({ "error": "Device is not marked as controlled endpoint" }));
    }
    Json(serde_json::json!({
        "type": "access_token",
        "access_token": "",
        "user": compat_user_payload(peer_id.trim(), "device", 1),
        "device": {
            "id": peer_id.trim(),
            "is_controlled": true,
            "skip_login": true
        }
    }))
}

async fn current_user_post(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)
        .map_err(|_| auth_err("Invalid token"))?;
    let user = state
        .pm
        .db
        .get_user_by_id(claims.sub)
        .await
        .map_err(internal_err)?;
    let user = match user {
        Some(v) => v,
        None => return Err(auth_err("Invalid token")),
    };
    Ok(Json(compat_user_payload(&user.username, &user.role, user.status)))
}

async fn users_dispatch(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<PagingQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    let users = if claims.role == "admin" {
        state.pm.db.list_users().await.map_err(internal_err)?
    } else {
        match state.pm.db.get_user_by_id(claims.sub).await.map_err(internal_err)? {
            Some(u) => vec![u],
            None => vec![],
        }
    };
    let users: Vec<_> = match q.status.as_deref() {
        Some("1") => users.into_iter().filter(|u| u.status == 1).collect(),
        Some("0") => users.into_iter().filter(|u| u.status == 0).collect(),
        _ => users,
    };

    if q.current.is_some() || q.page_size.is_some() {
        let current = q.current.unwrap_or(1).max(1);
        let page_size = q.page_size.unwrap_or(100).clamp(1, 500);
        let start = (current - 1) * page_size;
        let data: Vec<serde_json::Value> = users
            .iter()
            .skip(start)
            .take(page_size)
            .map(|u| compat_user_payload(&u.username, &u.role, u.status))
            .collect();
        return Ok(Json(serde_json::json!({ "total": users.len(), "data": data })));
    }
    let list: Vec<UserDto> = users
        .into_iter()
        .map(|u| UserDto {
            id: u.id,
            username: u.username,
            role: u.role,
            status: u.status,
            created_at: u.created_at,
        })
        .collect();
    Ok(Json(serde_json::to_value(list).unwrap_or_else(|_| serde_json::json!([]))))
}

async fn peers_dispatch(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<PagingQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    let rows = state.pm.db.list_peers().await.map_err(internal_err)?;
    let runtime = state.pm.get_runtime_status().await;
    let allow_set = if claims.role == "admin" {
        None
    } else {
        let direct = state
            .pm
            .db
            .list_user_client_acl(claims.sub)
            .await
            .map_err(internal_err)?;
        let grouped = state
            .pm
            .db
            .list_group_peers_for_user(claims.sub)
            .await
            .map_err(internal_err)?;
        let mut all = HashSet::new();
        all.extend(direct);
        all.extend(grouped);
        Some(all)
    };
    let filtered: Vec<_> = rows
        .into_iter()
        .filter(|r| match &allow_set {
            Some(ids) => ids.contains(&r.id) && r.is_controlled != 0,
            None => true,
        })
        .collect();

    let filtered: Vec<_> = match q.status.as_deref() {
        Some("1") => filtered.into_iter().filter(|r| r.status.unwrap_or(1) != 0).collect(),
        Some("0") => filtered.into_iter().filter(|r| r.status.unwrap_or(1) == 0).collect(),
        _ => filtered,
    };

    if q.current.is_some() || q.page_size.is_some() {
        let current = q.current.unwrap_or(1).max(1);
        let page_size = q.page_size.unwrap_or(100).clamp(1, 500);
        let start = (current - 1) * page_size;
        let data: Vec<serde_json::Value> = filtered
            .iter()
            .skip(start)
            .take(page_size)
            .map(|r| {
                let info = serde_json::from_str::<serde_json::Value>(&r.info)
                    .unwrap_or_else(|_| serde_json::json!({}));
                serde_json::json!({
                    "id": r.id,
                    "name": r.name.clone().unwrap_or_default(),
                    "info": info,
                    "status": r.status.unwrap_or(1),
                    "is_controlled": r.is_controlled != 0,
                    "user": "",
                    "user_name": "",
                    "device_group_name": "",
                    "note": r.note.clone().unwrap_or_default(),
                })
            })
            .collect();
        return Ok(Json(serde_json::json!({ "total": filtered.len(), "data": data })));
    }

    let out: Vec<ClientDto> = filtered
        .into_iter()
        .map(|r| {
            let rt = runtime.get(&r.id);
            ClientDto {
                id: r.id,
                name: r.name,
                created_at: r.created_at,
                status: r.status,
                is_controlled: r.is_controlled != 0,
                note: r.note,
                online: rt.map(|x| x.online).unwrap_or(false),
                last_seen_secs: rt.map(|x| x.last_seen_secs),
                ip: rt.map(|x| x.ip.clone()).unwrap_or_default(),
            }
        })
        .collect();
    Ok(Json(serde_json::to_value(out).unwrap_or_else(|_| serde_json::json!([]))))
}

async fn device_group_accessible(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<PagingQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    let groups = state.pm.db.list_groups().await.map_err(internal_err)?;
    let visible: Vec<_> = if claims.role == "admin" {
        groups
    } else {
        let ids = state
            .pm
            .db
            .list_user_group_acl(claims.sub)
            .await
            .map_err(internal_err)?;
        let set: HashSet<i64> = ids.into_iter().collect();
        groups.into_iter().filter(|g| set.contains(&g.id)).collect()
    };
    let current = q.current.unwrap_or(1).max(1);
    let page_size = q.page_size.unwrap_or(100).clamp(1, 500);
    let start = (current - 1) * page_size;
    let data: Vec<serde_json::Value> = visible
        .iter()
        .skip(start)
        .take(page_size)
        .map(|g| serde_json::json!({"name": g.name}))
        .collect();
    Ok(Json(serde_json::json!({ "total": visible.len(), "data": data })))
}
async fn login(
    Extension(state): Extension<Arc<AppState>>,
    Json(req): Json<LoginReq>,
) -> Result<Json<LoginResp>, (StatusCode, Json<ApiError>)> {
    let user = state
        .pm
        .db
        .get_user_by_name(req.username.trim())
        .await
        .map_err(internal_err)?;
    let user = match user {
        Some(v) => v,
        None => return Err(auth_err("Invalid username or password")),
    };
    if user.status == 0 {
        return Err(auth_err("User is disabled"));
    }
    let ok = bcrypt::verify(req.password, &user.password_hash).unwrap_or(false);
    if !ok {
        return Err(auth_err("Invalid username or password"));
    }
    let claims = Claims {
        sub: user.id,
        username: user.username.clone(),
        role: user.role.clone(),
        exp: (chrono::Utc::now().timestamp() + 12 * 3600) as usize,
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.jwt_secret.as_bytes()),
    )
    .map_err(internal_err)?;
    Ok(Json(LoginResp {
        token,
        role: claims.role,
        username: claims.username,
        user_id: user.id,
    }))
}

async fn current_user(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<CurrentUserResp>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    Ok(Json(CurrentUserResp {
        id: claims.sub,
        username: claims.username,
        role: claims.role.clone(),
        is_admin: claims.role == "admin",
    }))
}

async fn logout() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true }))
}

async fn list_users(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<UserDto>>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    require_admin(&claims)?;
    let users = state.pm.db.list_users().await.map_err(internal_err)?;
    Ok(Json(
        users
            .into_iter()
            .map(|u| UserDto {
                id: u.id,
                username: u.username,
                role: u.role,
                status: u.status,
                created_at: u.created_at,
            })
            .collect(),
    ))
}

async fn create_user(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateUserReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    require_admin(&claims)?;
    let username = req.username.trim();
    if username.len() < 3 || req.password.len() < 6 {
        return Err(bad_req("Username >=3 chars, password >=6 chars"));
    }
    let role = req.role.unwrap_or_else(|| "user".to_owned());
    if role != "admin" && role != "user" {
        return Err(bad_req("Role must be admin or user"));
    }
    let hash = bcrypt::hash(req.password, bcrypt::DEFAULT_COST).map_err(internal_err)?;
    state
        .pm
        .db
        .create_user(username, &hash, &role)
        .await
        .map_err(internal_err)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn enable_user(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path(user_id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    set_user_status(state, headers, user_id, 1).await
}

async fn disable_user(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path(user_id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    set_user_status(state, headers, user_id, 0).await
}

async fn set_user_status(
    state: Arc<AppState>,
    headers: HeaderMap,
    user_id: i64,
    status: i64,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    require_admin(&claims)?;
    if claims.sub == user_id && status == 0 {
        return Err(bad_req("Cannot disable current login user"));
    }
    let user = state.pm.db.get_user_by_id(user_id).await.map_err(internal_err)?;
    if user.is_none() {
        return Err(not_found("User not found"));
    }
    state
        .pm
        .db
        .set_user_status(user_id, status)
        .await
        .map_err(internal_err)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn delete_user(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path(user_id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    require_admin(&claims)?;
    if claims.sub == user_id {
        return Err(bad_req("Cannot delete current login user"));
    }
    state
        .pm
        .db
        .delete_user(user_id)
        .await
        .map_err(internal_err)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn list_clients(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<ClientDto>>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    let rows = state.pm.db.list_peers().await.map_err(internal_err)?;
    let runtime = state.pm.get_runtime_status().await;
    let allow_set = if claims.role == "admin" {
        None
    } else {
        let direct = state
            .pm
            .db
            .list_user_client_acl(claims.sub)
            .await
            .map_err(internal_err)?;
        let grouped = state
            .pm
            .db
            .list_group_peers_for_user(claims.sub)
            .await
            .map_err(internal_err)?;
        let mut all = HashSet::new();
        all.extend(direct);
        all.extend(grouped);
        Some(all)
    };
    let out = rows
        .into_iter()
        .filter(|r| match &allow_set {
            Some(ids) => ids.contains(&r.id) && r.is_controlled != 0,
            None => true,
        })
        .map(|r| {
            let rt = runtime.get(&r.id);
            ClientDto {
                id: r.id,
                name: r.name,
                created_at: r.created_at,
                status: r.status,
                is_controlled: r.is_controlled != 0,
                note: r.note,
                online: rt.map(|x| x.online).unwrap_or(false),
                last_seen_secs: rt.map(|x| x.last_seen_secs),
                ip: rt.map(|x| x.ip.clone()).unwrap_or_default(),
            }
        })
        .collect();
    Ok(Json(out))
}

async fn enable_peer(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path(peer_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    set_peer_status(state, headers, peer_id, 1).await
}

async fn disable_peer(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path(peer_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    set_peer_status(state, headers, peer_id, 0).await
}

async fn update_peer_name(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path(peer_id): Path<String>,
    Json(req): Json<UpdatePeerNameReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    require_admin(&claims)?;
    let peer_id = peer_id.trim().to_owned();
    let peer = state
        .pm
        .db
        .get_peer_record(&peer_id)
        .await
        .map_err(internal_err)?;
    if peer.is_none() {
        return Err(not_found("Peer not found"));
    }
    state
        .pm
        .db
        .set_peer_name(&peer_id, req.name.as_deref())
        .await
        .map_err(internal_err)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn mark_controlled_peer(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path(peer_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    set_peer_controlled(state, headers, peer_id, 1).await
}

async fn unmark_controlled_peer(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path(peer_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    set_peer_controlled(state, headers, peer_id, 0).await
}

async fn set_peer_status(
    state: Arc<AppState>,
    headers: HeaderMap,
    peer_id: String,
    status: i64,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    require_admin(&claims)?;
    state
        .pm
        .db
        .set_peer_status(peer_id.trim(), status)
        .await
        .map_err(internal_err)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn set_peer_controlled(
    state: Arc<AppState>,
    headers: HeaderMap,
    peer_id: String,
    is_controlled: i64,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    require_admin(&claims)?;
    let peer_id = peer_id.trim().to_owned();
    let peer = state
        .pm
        .db
        .get_peer_record(&peer_id)
        .await
        .map_err(internal_err)?;
    if peer.is_none() {
        return Err(not_found("Peer not found"));
    }
    state
        .pm
        .db
        .set_peer_controlled(&peer_id, is_controlled)
        .await
        .map_err(internal_err)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn delete_peer(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path(peer_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    require_admin(&claims)?;
    state
        .pm
        .db
        .delete_peer(peer_id.trim())
        .await
        .map_err(internal_err)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn list_user_peers(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path(user_id): Path<i64>,
) -> Result<Json<Vec<String>>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    if claims.role != "admin" && claims.sub != user_id {
        return Err(auth_err("Permission denied"));
    }
    let ids = state
        .pm
        .db
        .list_user_client_acl(user_id)
        .await
        .map_err(internal_err)?;
    Ok(Json(ids))
}

async fn grant_user_peer(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path((user_id, peer_id)): Path<(i64, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    require_admin(&claims)?;
    let peer_id = peer_id.trim().to_owned();
    let peer = state
        .pm
        .db
        .get_peer_record(&peer_id)
        .await
        .map_err(internal_err)?;
    let peer = match peer {
        Some(v) => v,
        None => return Err(not_found("Peer not found")),
    };
    if peer.is_controlled == 0 {
        return Err(bad_req("Only controlled devices can be assigned to users"));
    }
    state
        .pm
        .db
        .grant_user_client_acl(user_id, &peer_id)
        .await
        .map_err(internal_err)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn revoke_user_peer(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path((user_id, peer_id)): Path<(i64, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    require_admin(&claims)?;
    state
        .pm
        .db
        .revoke_user_client_acl(user_id, peer_id.trim())
        .await
        .map_err(internal_err)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn list_user_groups(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path(user_id): Path<i64>,
) -> Result<Json<Vec<i64>>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    if claims.role != "admin" && claims.sub != user_id {
        return Err(auth_err("Permission denied"));
    }
    let ids = state
        .pm
        .db
        .list_user_group_acl(user_id)
        .await
        .map_err(internal_err)?;
    Ok(Json(ids))
}

async fn grant_user_group(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path((user_id, group_id)): Path<(i64, i64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    require_admin(&claims)?;
    state
        .pm
        .db
        .grant_user_group_acl(user_id, group_id)
        .await
        .map_err(internal_err)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn revoke_user_group(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path((user_id, group_id)): Path<(i64, i64)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    require_admin(&claims)?;
    state
        .pm
        .db
        .revoke_user_group_acl(user_id, group_id)
        .await
        .map_err(internal_err)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn list_groups(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<GroupDto>>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    require_admin(&claims)?;
    let rows = state.pm.db.list_groups().await.map_err(internal_err)?;
    Ok(Json(
        rows.into_iter()
            .map(|g| GroupDto {
                id: g.id,
                name: g.name,
                created_at: g.created_at,
            })
            .collect(),
    ))
}

async fn create_group(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<CreateGroupReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    require_admin(&claims)?;
    let name = req.name.trim();
    if name.len() < 2 {
        return Err(bad_req("Group name must be at least 2 chars"));
    }
    state.pm.db.create_group(name).await.map_err(internal_err)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn delete_group(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path(group_id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    require_admin(&claims)?;
    state.pm.db.delete_group(group_id).await.map_err(internal_err)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn list_group_peers(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path(group_id): Path<i64>,
) -> Result<Json<Vec<String>>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    require_admin(&claims)?;
    let rows = state
        .pm
        .db
        .list_group_peers(group_id)
        .await
        .map_err(internal_err)?;
    Ok(Json(rows))
}

async fn add_group_peer(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path((group_id, peer_id)): Path<(i64, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    require_admin(&claims)?;
    let peer_id = peer_id.trim().to_owned();
    let peer = state
        .pm
        .db
        .get_peer_record(&peer_id)
        .await
        .map_err(internal_err)?;
    let peer = match peer {
        Some(v) => v,
        None => return Err(not_found("Peer not found")),
    };
    if peer.is_controlled == 0 {
        return Err(bad_req("Only controlled devices can be added into groups"));
    }
    state
        .pm
        .db
        .add_group_peer(group_id, &peer_id)
        .await
        .map_err(internal_err)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn remove_group_peer(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Path((group_id, peer_id)): Path<(i64, String)>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    require_admin(&claims)?;
    state
        .pm
        .db
        .remove_group_peer(group_id, peer_id.trim())
        .await
        .map_err(internal_err)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}
async fn list_conn_audits(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<AuditQuery>,
) -> Result<Json<Vec<AuditDto>>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    require_admin(&claims)?;
    let rows = list_punch_req_audits(q.offset.unwrap_or(0), q.limit.unwrap_or(50)).await;
    Ok(Json(
        rows
            .into_iter()
            .map(|x| AuditDto {
                timestamp: x.timestamp,
                from_ip: x.from_ip,
                to_ip: x.to_ip,
                to_id: x.to_id,
            })
            .collect(),
    ))
}

async fn group_tree(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    require_admin(&claims)?;

    let groups = state.pm.db.list_groups().await.map_err(internal_err)?;
    let peers = state.pm.db.list_peers().await.map_err(internal_err)?;
    let runtime = state.pm.get_runtime_status().await;
    let peer_map: HashMap<String, crate::database::PeerRecord> =
        peers.into_iter().map(|p| (p.id.clone(), p)).collect();

    let mut out = Vec::with_capacity(groups.len());
    for g in groups {
        let member_ids = state
            .pm
            .db
            .list_group_peers(g.id)
            .await
            .map_err(internal_err)?;
        let members: Vec<serde_json::Value> = member_ids
            .into_iter()
            .map(|id| {
                if let Some(p) = peer_map.get(&id) {
                    let rt = runtime.get(&id);
                    serde_json::json!({
                        "id": id,
                        "name": p.name.clone().unwrap_or_default(),
                        "status": p.status.unwrap_or(1),
                        "is_controlled": p.is_controlled != 0,
                        "online": rt.map(|x| x.online).unwrap_or(false),
                        "last_seen_secs": rt.map(|x| x.last_seen_secs),
                    })
                } else {
                    serde_json::json!({ "id": id })
                }
            })
            .collect();
        out.push(serde_json::json!({
            "id": g.id,
            "name": g.name,
            "created_at": g.created_at,
            "devices": members
        }));
    }
    Ok(Json(out))
}

async fn user_tree(
    Extension(state): Extension<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<serde_json::Value>>, (StatusCode, Json<ApiError>)> {
    let claims = auth_claims(&state, &headers)?;
    let users = if claims.role == "admin" {
        state.pm.db.list_users().await.map_err(internal_err)?
    } else {
        match state
            .pm
            .db
            .get_user_by_id(claims.sub)
            .await
            .map_err(internal_err)?
        {
            Some(u) => vec![u],
            None => vec![],
        }
    };
    let groups = state.pm.db.list_groups().await.map_err(internal_err)?;
    let peers = state.pm.db.list_peers().await.map_err(internal_err)?;
    let runtime = state.pm.get_runtime_status().await;
    let group_map: HashMap<i64, crate::database::DeviceGroup> =
        groups.into_iter().map(|g| (g.id, g)).collect();
    let peer_map: HashMap<String, crate::database::PeerRecord> =
        peers.into_iter().map(|p| (p.id.clone(), p)).collect();

    let mut out = Vec::with_capacity(users.len());
    for u in users {
        let direct_ids = state
            .pm
            .db
            .list_user_client_acl(u.id)
            .await
            .map_err(internal_err)?;
        let group_ids = state
            .pm
            .db
            .list_user_group_acl(u.id)
            .await
            .map_err(internal_err)?;

        let direct_devices: Vec<serde_json::Value> = direct_ids
            .into_iter()
            .map(|id| {
                if let Some(p) = peer_map.get(&id) {
                    let rt = runtime.get(&id);
                    serde_json::json!({
                        "id": id,
                        "name": p.name.clone().unwrap_or_default(),
                        "status": p.status.unwrap_or(1),
                        "is_controlled": p.is_controlled != 0,
                        "online": rt.map(|x| x.online).unwrap_or(false),
                    })
                } else {
                    serde_json::json!({ "id": id })
                }
            })
            .collect();

        let mut groups_json = Vec::new();
        for gid in group_ids {
            let members = state
                .pm
                .db
                .list_group_peers(gid)
                .await
                .map_err(internal_err)?;
            let peers_json: Vec<serde_json::Value> = members
                .into_iter()
                .map(|id| {
                    if let Some(p) = peer_map.get(&id) {
                        let rt = runtime.get(&id);
                        serde_json::json!({
                            "id": id,
                            "name": p.name.clone().unwrap_or_default(),
                            "status": p.status.unwrap_or(1),
                            "is_controlled": p.is_controlled != 0,
                            "online": rt.map(|x| x.online).unwrap_or(false),
                        })
                    } else {
                        serde_json::json!({ "id": id })
                    }
                })
                .collect();
            let g = group_map.get(&gid);
            groups_json.push(serde_json::json!({
                "id": gid,
                "name": g.map(|x| x.name.clone()).unwrap_or_else(|| format!("Group-{gid}")),
                "devices": peers_json
            }));
        }

        out.push(serde_json::json!({
            "id": u.id,
            "username": u.username,
            "role": u.role,
            "status": u.status,
            "groups": groups_json,
            "direct_devices": direct_devices
        }));
    }
    Ok(Json(out))
}

fn auth_claims(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Claims, (StatusCode, Json<ApiError>)> {
    let token = headers
        .get("token")
        .or_else(|| headers.get(header::AUTHORIZATION))
        .and_then(|v| v.to_str().ok())
        .map(|v| v.strip_prefix("Bearer ").unwrap_or(v))
        .ok_or_else(|| auth_err("Missing token"))?;
    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| auth_err("Invalid token"))?;
    Ok(data.claims)
}

fn require_admin(claims: &Claims) -> Result<(), (StatusCode, Json<ApiError>)> {
    if claims.role != "admin" {
        return Err(auth_err("Admin only"));
    }
    Ok(())
}

fn internal_err<E: std::fmt::Display>(err: E) -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ApiError {
            message: err.to_string(),
        }),
    )
}

fn auth_err(msg: &str) -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(ApiError {
            message: msg.to_owned(),
        }),
    )
}

fn bad_req(msg: &str) -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ApiError {
            message: msg.to_owned(),
        }),
    )
}

fn not_found(msg: &str) -> (StatusCode, Json<ApiError>) {
    (
        StatusCode::NOT_FOUND,
        Json(ApiError {
            message: msg.to_owned(),
        }),
    )
}

const ADMIN_LOGIN_HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>RustDesk Console Login</title>
  <link rel="stylesheet" href="https://unpkg.com/element-plus@2.11.5/dist/index.css" />
  <link rel="stylesheet" href="/admin/style.css" />
</head>
<body class="bg-grid">
  <main class="login-wrap">
    <section class="glass card login-card">
      <h1>RustDesk Console</h1>
      <p class="subtle">Use your admin or delegated user account.</p>
      <div class="row">
        <label>Username</label>
        <input id="username" placeholder="Enter username" value="admin" />
      </div>
      <div class="row">
        <label>Password</label>
        <input id="password" placeholder="Enter password" type="password" />
      </div>
      <div class="row">
        <button id="loginBtn" class="btn-primary w-full el-button el-button--primary">Sign in</button>
      </div>
      <div id="loginMsg" class="hint"></div>
      <p class="subtle tiny">Default account: admin / admin123456</p>
    </section>
  </main>
  <script src="/admin/login.js"></script>
</body>
</html>
"##;

const ADMIN_DASHBOARD_HTML: &str = r##"<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>RustDesk Workplace</title>
  <link rel="stylesheet" href="https://unpkg.com/element-plus@2.11.5/dist/index.css" />
  <link rel="stylesheet" href="/admin/style.css" />
</head>
<body class="work-bg">
  <div class="console-shell">
    <aside class="sidebar glass">
      <div class="sidebar-brand">
        <h1 class="brand">RustDesk Workplace</h1>
        <p class="subtle" id="welcomeText">加载中...</p>
      </div>
      <nav class="menu">
        <button class="menu-item active" data-panel="overviewPanel">总览</button>
        <button class="menu-item" data-panel="clientsPanel">设备管理</button>
        <button class="menu-item admin-only" data-panel="usersPanel">用户管理</button>
        <button class="menu-item" data-panel="myTreePanel">用户关联树</button>
        <button class="menu-item admin-only" data-panel="groupsPanel">设备组管理</button>
        <button class="menu-item admin-only" data-panel="auditsPanel">连接审计</button>
      </nav>
      <div class="sidebar-foot subtle tiny">API Base: /api</div>
    </aside>

    <main class="main-pane">
      <header class="topbar glass">
        <div>
          <h2 id="panelTitle">总览</h2>
          <p class="subtle">当前时间：<strong id="clockText">--:--:--</strong></p>
        </div>
        <div class="row-inline">
          <button id="refreshAllBtn" class="btn-primary el-button el-button--primary">刷新全局</button>
          <button id="refreshAuditsBtn" class="btn-ghost el-button">刷新审计</button>
          <button id="logoutBtn" class="btn-ghost el-button">退出登录</button>
        </div>
      </header>

      <datalist id="peerIdCandidates"></datalist>
      <div id="peerSuggest" class="peer-suggest hidden"></div>
      <div id="groupAclModal" class="modal-mask hidden">
        <div class="modal-card glass">
          <div class="panel-head">
            <h2 id="groupAclTitle">设备组成员管理</h2>
          </div>
          <p id="groupAclMeta" class="subtle tiny">-</p>
          <div class="row">
            <label class="form-label">添加设备</label>
            <div class="row-inline">
              <input id="groupAclPeerInput" class="aclPeer" placeholder="请输入设备ID" />
              <button id="groupAclAddBtn" class="btn-primary el-button el-button--primary">添加</button>
            </div>
          </div>
          <div class="row">
            <label class="form-label">当前设备</label>
            <div id="groupAclMembers" class="tag-wall subtle">暂无设备</div>
          </div>
          <div class="row-inline modal-actions">
            <button id="groupAclCloseBtn" class="btn-ghost el-button">关闭</button>
          </div>
        </div>
      </div>

      <div id="userAclModal" class="modal-mask hidden">
        <div class="modal-card modal-lg glass">
          <div class="panel-head">
            <h2 id="userAclTitle">用户权限管理</h2>
          </div>
          <p id="userAclMeta" class="subtle tiny">-</p>
          <div class="row row-inline">
            <div>
              <label class="form-label">授权设备</label>
              <div class="row-inline">
                <input id="userAclPeerInput" class="aclPeer" placeholder="请输入设备ID" />
                <button id="userAclAddPeerBtn" class="btn-primary el-button el-button--primary">添加设备</button>
              </div>
            </div>
            <div>
              <label class="form-label">授权设备组</label>
              <div class="row-inline">
                <select id="userAclGroupSelect"></select>
                <button id="userAclAddGroupBtn" class="btn-primary el-button el-button--primary">添加设备组</button>
              </div>
            </div>
          </div>
          <div class="row">
            <label class="form-label">当前设备授权</label>
            <div id="userAclPeers" class="tag-wall subtle">暂无设备授权</div>
          </div>
          <div class="row">
            <label class="form-label">当前设备组授权</label>
            <div id="userAclGroups" class="tag-wall subtle">暂无设备组授权</div>
          </div>
          <div class="row-inline modal-actions">
            <button id="userAclCloseBtn" class="btn-ghost el-button">关闭</button>
          </div>
        </div>
      </div>

      <section class="panel-view active" id="overviewPanel" data-title="总览">
        <section class="kpi-grid">
          <article class="kpi-card glass">
            <p>用户总数</p>
            <h3 id="kpiUsers">0</h3>
          </article>
          <article class="kpi-card glass">
            <p>启用用户</p>
            <h3 id="kpiUsersEnabled">0</h3>
          </article>
          <article class="kpi-card glass">
            <p>设备总数</p>
            <h3 id="kpiPeers">0</h3>
          </article>
          <article class="kpi-card glass">
            <p>在线设备</p>
            <h3 id="kpiPeersOnline">0</h3>
          </article>
        </section>
        <section class="card glass panel">
          <div class="panel-head">
            <h2>工作台说明</h2>
            <span class="subtle tiny">左侧切换模块，右侧执行管理操作</span>
          </div>
          <p class="subtle">
            支持设备被控端标记、用户授权、设备组授权和连接审计。设备ID输入框支持模糊搜索与回填。
          </p>
        </section>
      </section>

      <section class="panel-view" id="clientsPanel" data-title="设备管理">
        <section class="card glass panel">
          <div class="panel-head">
            <h2>设备管理</h2>
            <span class="subtle tiny">在线态 + DB 状态 + 被控端标记</span>
          </div>
          <div class="table-wrap">
            <table id="clientsTbl">
              <thead><tr><th>设备ID</th><th>名称</th><th>在线状态</th><th>DB状态</th><th>设备类型</th><th>最近心跳(秒)</th><th>IP</th><th>创建时间</th><th>操作</th></tr></thead>
              <tbody></tbody>
            </table>
          </div>
        </section>
      </section>

      <section class="panel-view" id="myTreePanel" data-title="用户关联树">
        <section class="card glass panel">
          <div class="panel-head">
            <h2>用户关联树</h2>
            <span class="subtle tiny">用户 -> 设备组 -> 设备，以及直接授权设备</span>
          </div>
          <div id="userTreeBox" class="tree-box subtle">加载中...</div>
        </section>
      </section>

      <section class="panel-view" id="usersPanel" data-title="用户管理">
        <section class="card glass panel" id="userCard">
          <div class="panel-head">
            <h2>用户管理</h2>
            <span class="subtle tiny">创建、启停、删除、授权</span>
          </div>
          <div class="row row-inline">
            <input id="newUser" placeholder="新用户名" />
            <input id="newPass" placeholder="新密码" type="password" />
            <select id="newRole">
              <option value="user">user</option>
              <option value="admin">admin</option>
            </select>
            <button id="createUserBtn" class="btn-primary el-button el-button--primary">创建用户</button>
          </div>
          <div class="table-wrap">
            <table id="usersTbl">
              <thead><tr><th>ID</th><th>用户名</th><th>角色</th><th>状态</th><th>创建时间</th><th>设备授权</th><th>设备组授权</th><th>操作</th></tr></thead>
              <tbody></tbody>
            </table>
          </div>
        </section>
      </section>

      <section class="panel-view" id="groupsPanel" data-title="设备组管理">
        <section class="card glass panel" id="groupCard">
          <div class="panel-head">
            <h2>设备组管理</h2>
            <span class="subtle tiny">创建组、添加设备、授权给用户</span>
          </div>
          <div class="row row-inline">
            <input id="newGroup" placeholder="设备组名称" />
            <button id="createGroupBtn" class="btn-primary el-button el-button--primary">创建设备组</button>
          </div>
          <div class="table-wrap">
            <table id="groupsTbl">
              <thead><tr><th>ID</th><th>名称</th><th>成员设备</th><th>创建时间</th><th>操作</th></tr></thead>
              <tbody></tbody>
            </table>
          </div>
        </section>
        <section class="card glass panel" id="groupTreeCard">
          <div class="panel-head">
            <h2>设备组树</h2>
            <span class="subtle tiny">设备组 -> 设备</span>
          </div>
          <div id="groupTreeBox" class="tree-box subtle">加载中...</div>
        </section>
      </section>

      <section class="panel-view" id="auditsPanel" data-title="连接审计">
        <section class="card glass panel" id="auditCard">
          <div class="panel-head">
            <h2>连接审计</h2>
            <span class="subtle tiny">最近打洞请求记录</span>
          </div>
          <div class="table-wrap">
            <table id="auditTbl">
              <thead><tr><th>时间(UTC)</th><th>来源IP</th><th>目标设备ID</th><th>目标IP</th></tr></thead>
              <tbody></tbody>
            </table>
          </div>
        </section>
      </section>
    </main>
  </div>
  <script src="/admin/dashboard.js"></script>
</body>
</html>
"##;

const ADMIN_STYLE_CSS: &str = r##"
:root {
  --bg: #f5f7fa;
  --ink: #303133;
  --muted: #606266;
  --line: #dcdfe6;
  --card: #ffffff;
  --danger: #dc2626;
  --accent: #409eff;
  --accent-2: #337ecc;
  --menu: #ffffff;
  --menu-2: #ffffff;
  --el-shadow-light: 0 2px 12px 0 rgba(0, 0, 0, 0.1);
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  color: var(--ink);
  font: 14px/1.6 "Helvetica Neue", Helvetica, "PingFang SC", "Microsoft YaHei", Arial, sans-serif;
}

.bg-grid {
  min-height: 100vh;
  background: var(--bg);
}

.login-wrap {
  min-height: 100vh;
  display: grid;
  place-items: center;
  padding: 18px;
}

.login-card {
  width: min(420px, 100%);
}

.hint {
  margin: 8px 0 10px;
  color: var(--muted);
}

.hint.ok {
  color: #166534;
}

.hint.err {
  color: var(--danger);
}

.w-full {
  width: 100%;
}

.work-bg {
  background: var(--bg);
  min-height: 100vh;
}

.glass {
  background: var(--card);
  border: 1px solid var(--line);
  box-shadow: var(--el-shadow-light);
  backdrop-filter: none;
}

.card {
  border-radius: 8px;
  padding: 12px;
}

.brand {
  margin: 0;
  font-size: 22px;
  letter-spacing: .2px;
}

h2 {
  margin: 0;
  font-size: 16px;
}

h3 {
  margin: 0;
  font-size: 28px;
  line-height: 1.2;
}

.subtle {
  margin: 0;
  color: var(--muted);
}

.tiny {
  font-size: 12px;
}

.row {
  margin-bottom: 12px;
}

.row-inline {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

input, select, button {
  border-radius: 4px;
  border: 1px solid #dcdfe6;
  padding: 8px 11px;
  font-size: 14px;
  background: #fff;
  transition: all .2s;
}

input, select {
  min-width: 120px;
}

button {
  cursor: pointer;
}

button:not(.btn-primary):not(.btn-danger):not(.menu-item) {
  border-color: #dcdfe6;
  color: #606266;
  background: #fff;
}

button:not(.btn-primary):not(.btn-danger):not(.menu-item):hover {
  color: #409eff;
  border-color: #c6e2ff;
  background: #ecf5ff;
}

.btn-primary {
  border: 1px solid #409eff;
  color: #fff;
  background: #409eff;
}

.btn-primary:hover {
  background: #66b1ff;
  border-color: #66b1ff;
}

.btn-ghost {
  background: #fff;
  color: #606266;
  border-color: #dcdfe6;
}

.btn-ghost:hover {
  color: #409eff;
  border-color: #c6e2ff;
  background: #ecf5ff;
}

.btn-danger {
  border: 1px solid #f56c6c;
  color: #fff;
  background: #f56c6c;
}

.btn-danger:hover {
  background: #f78989;
  border-color: #f78989;
}

.hidden {
  display: none !important;
}

.console-shell {
  min-height: 0;
  display: grid;
  grid-template-columns: 260px 1fr;
  gap: 10px;
  padding: 10px;
  align-items: start;
}

.sidebar {
  border-radius: 8px;
  padding: 10px;
  display: grid;
  grid-template-rows: auto auto auto;
  gap: 8px;
  background: var(--menu);
  color: var(--ink);
  box-shadow: none;
  border: 1px solid var(--line);
  align-self: start;
  position: sticky;
  top: 10px;
  max-height: calc(100vh - 20px);
  overflow: auto;
}

.sidebar .subtle {
  color: var(--muted);
}

.menu {
  display: grid;
  gap: 6px;
}

.menu-item {
  width: 100%;
  text-align: left;
  padding: 7px 10px;
  border-radius: 4px;
  border: 1px solid transparent;
  background: transparent;
  color: #606266;
  font-weight: 500;
}

.menu-item.active {
  background: #ecf5ff;
  border-color: #d9ecff;
  color: #409eff;
}

.menu-item:hover {
  background: #f5f7fa;
  color: #409eff;
}

.sidebar-foot {
  border-top: 1px solid var(--line);
  padding-top: 8px;
}

.main-pane {
  display: grid;
  gap: 10px;
}

.topbar {
  padding: 8px 12px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 6px;
}

.panel-view {
  display: none;
  gap: 10px;
}

.panel-view.active {
  display: grid;
}

.kpi-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}

.kpi-card {
  border-radius: 8px;
  padding: 10px;
  box-shadow: none;
}

.kpi-card p {
  margin: 0 0 8px;
  color: var(--muted);
}

.panel-head {
  margin-bottom: 8px;
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.table-wrap {
  overflow: auto;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: #fff;
}

.peer-name-wrap {
  display: flex;
  gap: 6px;
  align-items: center;
}

.peer-name-wrap input {
  min-width: 120px;
  width: 140px;
}

.tree-box {
  border: 1px solid var(--line);
  border-radius: 6px;
  background: #fff;
  padding: 10px 12px;
  max-height: 480px;
  overflow: auto;
}

.tree-list {
  margin: 0;
  padding-left: 18px;
}

.tree-list li {
  margin: 4px 0;
}

.tree-node {
  display: inline-flex;
  gap: 6px;
  align-items: center;
}

.tree-tag {
  display: inline-block;
  border: 1px solid #d9ecff;
  background: #ecf5ff;
  color: #409eff;
  border-radius: 4px;
  font-size: 12px;
  line-height: 1;
  padding: 3px 6px;
}

table {
  width: 100%;
  border-collapse: collapse;
  min-width: 860px;
}
th, td {
  text-align: left;
  border-bottom: 1px solid var(--line);
  padding: 8px 6px;
}
th {
  position: sticky;
  top: 0;
  z-index: 1;
  background: #f5f7fa;
  font-weight: 600;
  color: #606266;
}

.status-pill {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 99px;
  font-size: 12px;
  font-weight: 700;
}

.status-online {
  background: #dcfce7;
  color: #166534;
}

.status-offline {
  background: #fef3c7;
  color: #92400e;
}

.peer-suggest {
  position: fixed;
  z-index: 99;
  min-width: 180px;
  max-width: 420px;
  max-height: 220px;
  overflow: auto;
  background: #fff;
  border: 1px solid #dcdfe6;
  border-radius: 4px;
  box-shadow: var(--el-shadow-light);
}

.peer-suggest-item {
  width: 100%;
  text-align: left;
  border: none;
  border-bottom: 1px solid #ebeef5;
  border-radius: 0;
  padding: 8px 12px;
  background: #fff;
  color: #606266;
}

.peer-suggest-item:hover {
  background: #f5f7fa;
  color: #409eff;
}

.peer-suggest-item:last-child {
  border-bottom: none;
}

.modal-mask {
  position: fixed;
  inset: 0;
  z-index: 120;
  background: rgba(0, 0, 0, .35);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 12px;
}

.modal-card {
  width: min(460px, calc(100vw - 24px));
  border-radius: 8px;
  padding: 12px;
}

.modal-lg {
  width: min(760px, calc(100vw - 24px));
}

.modal-card .row {
  margin: 10px 0;
}

.modal-card input,
.modal-card select {
  width: 100%;
  min-width: 0;
}

.modal-actions {
  justify-content: flex-end;
}

.form-label {
  display: block;
  font-size: 12px;
  color: var(--muted);
  margin-bottom: 6px;
}

.tag-wall {
  min-height: 34px;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: #fafafa;
  padding: 6px;
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  border: 1px solid #d9ecff;
  background: #ecf5ff;
  color: #409eff;
  border-radius: 999px;
  padding: 4px 10px;
  font-size: 12px;
}

.chip button {
  border: none;
  background: transparent;
  color: inherit;
  padding: 0;
  line-height: 1;
  cursor: pointer;
  font-size: 14px;
}

@media (max-width: 1160px) {
  .console-shell {
    grid-template-columns: 220px 1fr;
  }
  .kpi-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 840px) {
  .console-shell {
    grid-template-columns: 1fr;
  }
  .sidebar {
    grid-template-rows: auto auto auto;
  }
  .menu {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .topbar {
    flex-direction: column;
    align-items: flex-start;
  }
  .kpi-grid {
    grid-template-columns: 1fr;
  }
}
"##;

const ADMIN_LOGIN_JS: &str = r##"(() => {
  const q = (s) => document.querySelector(s);
  const msg = (text, cls) => { const el = q("#loginMsg"); el.className = `hint ${cls || ""}`; el.textContent = text || ""; };
  localStorage.removeItem("adminToken");
  localStorage.removeItem("adminUser");
  q("#loginBtn").onclick = async () => {
    try {
      const res = await fetch("/api/admin/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: q("#username").value.trim(),
          password: q("#password").value
        })
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.message || `HTTP ${res.status}`);
      localStorage.setItem("adminToken", data.token || data.access_token || "");
      localStorage.setItem("adminUser", JSON.stringify({ user_id: data.user_id, username: data.username, role: data.role }));
      msg("Login successful, redirecting...", "ok");
      location.href = "/admin/dashboard";
    } catch (e) {
      msg(`Login failed: ${e.message}`, "err");
    }
  };
})();
"##;

const ADMIN_DASHBOARD_JS: &str = r##"(() => {
  const q = (s) => document.querySelector(s);
  const qa = (s) => Array.from(document.querySelectorAll(s));
  const token = localStorage.getItem("adminToken") || "";
  const me = JSON.parse(localStorage.getItem("adminUser") || "{}");
  if (!token) location.href = "/admin/login";

  q("#welcomeText").textContent = `${me.username || "unknown"} (${me.role || "-"})`;
  const panelTitle = q("#panelTitle");
  let currentPanel = "overviewPanel";

  function tickClock() {
    const now = new Date();
    q("#clockText").textContent = now.toLocaleTimeString();
  }
  tickClock();
  setInterval(tickClock, 1000);

  async function api(url, method = "GET", body) {
    const res = await fetch(url, {
      method,
      headers: {
        "Content-Type": "application/json",
        token,
      },
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    if (res.status === 401) {
      localStorage.removeItem("adminToken");
      localStorage.removeItem("adminUser");
      location.href = "/admin/login";
      throw new Error("Unauthorized");
    }
    if (!res.ok) throw new Error(data.message || `HTTP ${res.status}`);
    return data;
  }

  const esc = (s) => String(s || "").replace(/[&<>"']/g, (c) => ({ "&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;" }[c]));

  let usersCache = [];
  let peersCache = [];
  let groupsCache = [];
  let peerIds = [];

  const peerSuggest = q("#peerSuggest");
  let peerSuggestInput = null;
  const groupAclModal = q("#groupAclModal");
  const groupAclTitle = q("#groupAclTitle");
  const groupAclMeta = q("#groupAclMeta");
  const groupAclPeerInput = q("#groupAclPeerInput");
  const groupAclAddBtn = q("#groupAclAddBtn");
  const groupAclCloseBtn = q("#groupAclCloseBtn");
  const groupAclMembers = q("#groupAclMembers");
  const userAclModal = q("#userAclModal");
  const userAclTitle = q("#userAclTitle");
  const userAclMeta = q("#userAclMeta");
  const userAclPeerInput = q("#userAclPeerInput");
  const userAclAddPeerBtn = q("#userAclAddPeerBtn");
  const userAclGroupSelect = q("#userAclGroupSelect");
  const userAclAddGroupBtn = q("#userAclAddGroupBtn");
  const userAclCloseBtn = q("#userAclCloseBtn");
  const userAclPeers = q("#userAclPeers");
  const userAclGroups = q("#userAclGroups");

  const groupAclState = {
    groupId: null,
    name: "",
    members: [],
  };
  const userAclState = {
    userId: null,
    username: "",
    peers: [],
    groups: [],
  };

  function peerDisplay(peerId) {
    const id = String(peerId || "");
    const peer = peersCache.find((x) => String(x.id || "") === id);
    if (peer && peer.name) return `${peer.name} (${id})`;
    return id;
  }

  function groupDisplay(groupId) {
    const gid = Number(groupId);
    const group = groupsCache.find((x) => Number(x.id) === gid);
    if (group) return `${group.name} (${gid})`;
    return String(groupId || "");
  }

  function closeGroupAclModal() {
    if (!groupAclModal) return;
    groupAclModal.classList.add("hidden");
    hidePeerSuggest();
  }

  function closeUserAclModal() {
    if (!userAclModal) return;
    userAclModal.classList.add("hidden");
    hidePeerSuggest();
  }

  function renderGroupAclMembers() {
    if (!groupAclMembers) return;
    const members = groupAclState.members || [];
    if (!members.length) {
      groupAclMembers.innerHTML = `<span class="subtle tiny">暂无设备</span>`;
      return;
    }
    groupAclMembers.innerHTML = members
      .map((peerId) => `<span class="chip">
          <span>${esc(peerDisplay(peerId))}</span>
          <button type="button" data-act="group-acl-remove-peer" data-peer="${esc(peerId)}" title="移除">×</button>
        </span>`)
      .join("");
  }

  function renderUserAclPeers() {
    if (!userAclPeers) return;
    const peers = userAclState.peers || [];
    if (!peers.length) {
      userAclPeers.innerHTML = `<span class="subtle tiny">暂无设备授权</span>`;
      return;
    }
    userAclPeers.innerHTML = peers
      .map((peerId) => `<span class="chip">
          <span>${esc(peerDisplay(peerId))}</span>
          <button type="button" data-act="user-acl-remove-peer" data-peer="${esc(peerId)}" title="移除">×</button>
        </span>`)
      .join("");
  }

  function renderUserAclGroups() {
    if (!userAclGroups) return;
    const groups = userAclState.groups || [];
    if (!groups.length) {
      userAclGroups.innerHTML = `<span class="subtle tiny">暂无设备组授权</span>`;
      return;
    }
    userAclGroups.innerHTML = groups
      .map((groupId) => `<span class="chip">
          <span>${esc(groupDisplay(groupId))}</span>
          <button type="button" data-act="user-acl-remove-group" data-group="${esc(groupId)}" title="移除">×</button>
        </span>`)
      .join("");
  }

  function renderUserAclGroupOptions() {
    if (!userAclGroupSelect) return;
    const options = groupsCache
      .map((g) => `<option value="${esc(g.id)}">${esc(g.name)} (${esc(g.id)})</option>`)
      .join("");
    userAclGroupSelect.innerHTML = options || `<option value="">暂无设备组</option>`;
  }

  async function reloadGroupAclState() {
    if (!groupAclState.groupId) return;
    groupAclState.members = await api(`/api/groups/${groupAclState.groupId}/peers`).catch(() => []);
    renderGroupAclMembers();
  }

  async function reloadUserAclState() {
    if (!userAclState.userId) return;
    userAclState.peers = await api(`/api/users/${userAclState.userId}/peers`).catch(() => []);
    userAclState.groups = await api(`/api/users/${userAclState.userId}/groups`).catch(() => []);
    renderUserAclPeers();
    renderUserAclGroups();
  }

  async function openGroupAclModal(groupId, groupName) {
    groupAclState.groupId = Number(groupId);
    groupAclState.name = groupName || `Group-${groupId}`;
    groupAclTitle.textContent = "设备组成员管理";
    groupAclMeta.textContent = `${groupAclState.name} (ID: ${groupAclState.groupId})`;
    await reloadGroupAclState();
    groupAclModal.classList.remove("hidden");
    applyPeerInputHints();
    if (groupAclPeerInput) {
      groupAclPeerInput.value = "";
      setTimeout(() => {
        groupAclPeerInput.focus();
        showPeerSuggest(groupAclPeerInput);
      }, 0);
    }
  }

  async function openUserAclModal(userId, username) {
    userAclState.userId = Number(userId);
    userAclState.username = username || `User-${userId}`;
    userAclTitle.textContent = "用户权限管理";
    userAclMeta.textContent = `${userAclState.username} (ID: ${userAclState.userId})`;
    renderUserAclGroupOptions();
    await reloadUserAclState();
    userAclModal.classList.remove("hidden");
    applyPeerInputHints();
    if (userAclPeerInput) {
      userAclPeerInput.value = "";
      setTimeout(() => {
        userAclPeerInput.focus();
        showPeerSuggest(userAclPeerInput);
      }, 0);
    }
  }

  async function reloadAclViews() {
    await loadGroups();
    await loadUsers();
    await loadClients();
    await loadGroupTree();
    await loadUserTree();
  }

  groupAclCloseBtn?.addEventListener("click", closeGroupAclModal);
  userAclCloseBtn?.addEventListener("click", closeUserAclModal);

  groupAclModal?.addEventListener("click", (e) => {
    if (e.target === groupAclModal) closeGroupAclModal();
  });
  userAclModal?.addEventListener("click", (e) => {
    if (e.target === userAclModal) closeUserAclModal();
  });

  groupAclAddBtn?.addEventListener("click", async () => {
    const peerId = (groupAclPeerInput?.value || "").trim();
    if (!peerId) return alert("请填写设备ID");
    try {
      await api(`/api/groups/${groupAclState.groupId}/peers/${encodeURIComponent(peerId)}`, "POST");
      if (groupAclPeerInput) groupAclPeerInput.value = "";
      await reloadGroupAclState();
      await reloadAclViews();
    } catch (e) {
      alert(e.message);
    }
  });

  groupAclMembers?.addEventListener("click", async (e) => {
    const btn = e.target.closest('button[data-act="group-acl-remove-peer"]');
    if (!btn) return;
    const peerId = btn.getAttribute("data-peer");
    if (!peerId) return;
    try {
      await api(`/api/groups/${groupAclState.groupId}/peers/${encodeURIComponent(peerId)}`, "DELETE");
      await reloadGroupAclState();
      await reloadAclViews();
    } catch (e) {
      alert(e.message);
    }
  });

  userAclAddPeerBtn?.addEventListener("click", async () => {
    const peerId = (userAclPeerInput?.value || "").trim();
    if (!peerId) return alert("请填写设备ID");
    try {
      await api(`/api/users/${userAclState.userId}/peers/${encodeURIComponent(peerId)}`, "POST");
      if (userAclPeerInput) userAclPeerInput.value = "";
      await reloadUserAclState();
      await reloadAclViews();
    } catch (e) {
      alert(e.message);
    }
  });

  userAclAddGroupBtn?.addEventListener("click", async () => {
    const groupId = String(userAclGroupSelect?.value || "").trim();
    if (!groupId) return alert("请先选择设备组");
    try {
      await api(`/api/users/${userAclState.userId}/groups/${encodeURIComponent(groupId)}`, "POST");
      await reloadUserAclState();
      await reloadAclViews();
    } catch (e) {
      alert(e.message);
    }
  });

  userAclPeers?.addEventListener("click", async (e) => {
    const btn = e.target.closest('button[data-act="user-acl-remove-peer"]');
    if (!btn) return;
    const peerId = btn.getAttribute("data-peer");
    if (!peerId) return;
    try {
      await api(`/api/users/${userAclState.userId}/peers/${encodeURIComponent(peerId)}`, "DELETE");
      await reloadUserAclState();
      await reloadAclViews();
    } catch (e) {
      alert(e.message);
    }
  });

  userAclGroups?.addEventListener("click", async (e) => {
    const btn = e.target.closest('button[data-act="user-acl-remove-group"]');
    if (!btn) return;
    const groupId = btn.getAttribute("data-group");
    if (!groupId) return;
    try {
      await api(`/api/users/${userAclState.userId}/groups/${encodeURIComponent(groupId)}`, "DELETE");
      await reloadUserAclState();
      await reloadAclViews();
    } catch (e) {
      alert(e.message);
    }
  });

  function setPanelVisible(panelId, visible) {
    const panel = q(`#${panelId}`);
    const menu = q(`.menu-item[data-panel="${panelId}"]`);
    if (panel) panel.classList.toggle("hidden", !visible);
    if (menu) menu.classList.toggle("hidden", !visible);
    if (!visible && currentPanel === panelId) {
      showPanel("overviewPanel");
    }
  }

  function showPanel(panelId) {
    const target = q(`#${panelId}`);
    if (!target || target.classList.contains("hidden")) return;
    currentPanel = panelId;
    qa(".panel-view").forEach((panel) => panel.classList.toggle("active", panel.id === panelId));
    qa(".menu-item").forEach((item) => item.classList.toggle("active", item.dataset.panel === panelId));
    panelTitle.textContent = target.dataset.title || "工作台";
    hidePeerSuggest();
  }

  qa(".menu-item").forEach((item) => {
    item.addEventListener("click", () => showPanel(item.dataset.panel));
  });

  function renderKpis() {
    const enabledUsers = usersCache.filter((u) => Number(u.status) !== 0).length;
    const onlinePeers = peersCache.filter((p) => !!p.online).length;
    q("#kpiUsers").textContent = String(usersCache.length);
    q("#kpiUsersEnabled").textContent = String(enabledUsers);
    q("#kpiPeers").textContent = String(peersCache.length);
    q("#kpiPeersOnline").textContent = String(onlinePeers);
    const g = q("#kpiGroups");
    if (g) g.textContent = String(groupsCache.length);
  }

  function refreshPeerCandidates() {
    peerIds = peersCache.map((p) => String(p.id || "")).filter((x) => x.length > 0);
    const dl = q("#peerIdCandidates");
    if (!dl) return;
    dl.innerHTML = peerIds
      .slice(0, 1000)
      .map((id) => `<option value="${esc(id)}"></option>`)
      .join("");
  }

  function applyPeerInputHints() {
    qa("input.aclPeer").forEach((input) => {
      input.setAttribute("list", "peerIdCandidates");
      input.setAttribute("autocomplete", "off");
    });
  }

  function fuzzyPeerIds(text) {
    const key = String(text || "").trim().toLowerCase();
    if (!key) return peerIds.slice(0, 12);
    const prefix = [];
    const contains = [];
    for (const id of peerIds) {
      const low = id.toLowerCase();
      if (low.startsWith(key)) prefix.push(id);
      else if (low.includes(key)) contains.push(id);
    }
    return prefix.concat(contains).slice(0, 20);
  }

  function hidePeerSuggest() {
    if (!peerSuggest) return;
    peerSuggest.classList.add("hidden");
    peerSuggest.innerHTML = "";
    peerSuggestInput = null;
  }

  function showPeerSuggest(input) {
    if (!peerSuggest) return;
    const items = fuzzyPeerIds(input.value);
    if (!items.length) return hidePeerSuggest();
    peerSuggestInput = input;
    const rect = input.getBoundingClientRect();
    peerSuggest.style.left = `${Math.round(rect.left)}px`;
    peerSuggest.style.top = `${Math.round(rect.bottom + 4)}px`;
    peerSuggest.style.width = `${Math.max(180, Math.round(rect.width))}px`;
    peerSuggest.innerHTML = items
      .map((id) => `<button type="button" class="peer-suggest-item" data-peer-id="${esc(id)}">${esc(id)}</button>`)
      .join("");
    peerSuggest.classList.remove("hidden");
  }

  document.addEventListener("input", (e) => {
    const t = e.target;
    if (t && t.matches("input.aclPeer")) {
      showPeerSuggest(t);
    }
  });

  document.addEventListener("focusin", (e) => {
    const t = e.target;
    if (t && t.matches("input.aclPeer")) {
      showPeerSuggest(t);
    }
  });

  document.addEventListener("click", (e) => {
    const item = e.target.closest(".peer-suggest-item");
    if (item && peerSuggestInput) {
      peerSuggestInput.value = item.getAttribute("data-peer-id") || "";
      hidePeerSuggest();
      return;
    }
    const t = e.target;
    if (!(t && (t.matches("input.aclPeer") || t.closest("#peerSuggest")))) {
      hidePeerSuggest();
    }
  });

  window.addEventListener("resize", () => {
    if (peerSuggestInput) showPeerSuggest(peerSuggestInput);
  });
  window.addEventListener("scroll", () => {
    if (peerSuggestInput) showPeerSuggest(peerSuggestInput);
  }, true);

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      hidePeerSuggest();
      if (groupAclModal && !groupAclModal.classList.contains("hidden")) closeGroupAclModal();
      if (userAclModal && !userAclModal.classList.contains("hidden")) closeUserAclModal();
    }
  });

  async function loadGroups() {
    if (me.role !== "admin") {
      setPanelVisible("groupsPanel", false);
      groupsCache = [];
      renderKpis();
      return;
    }
    setPanelVisible("groupsPanel", true);
    groupsCache = await api("/api/groups").catch(() => []);
    const tbody = q("#groupsTbl tbody");
    if (!tbody) {
      renderKpis();
      return;
    }
    tbody.innerHTML = "";
    for (const g of groupsCache) {
      const members = await api(`/api/groups/${g.id}/peers`).catch(() => []);
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${g.id}</td><td>${esc(g.name)}</td><td>${esc(members.join(", "))}</td><td>${esc(g.created_at)}</td><td>
        <button class="btn-primary el-button el-button--primary el-button--small" data-group="${g.id}" data-group-name="${esc(g.name)}" data-act="groupManagePeers">成员管理</button>
        <button class="btn-danger el-button el-button--danger el-button--small" data-group="${g.id}" data-act="groupDelete">删组</button>
      </td>`;
      tbody.appendChild(tr);
    }
    renderKpis();
  }

  async function loadUsers() {
    if (me.role !== "admin") {
      setPanelVisible("usersPanel", false);
      usersCache = [];
      renderKpis();
      return;
    }
    setPanelVisible("usersPanel", true);
    usersCache = await api("/api/users").catch(() => []);
    const tbody = q("#usersTbl tbody");
    tbody.innerHTML = "";
    for (const u of usersCache) {
      const acl = await api(`/api/users/${u.id}/peers`).catch(() => []);
      const gAcl = await api(`/api/users/${u.id}/groups`).catch(() => []);
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${u.id}</td><td>${esc(u.username)}</td><td>${esc(u.role)}</td><td>${Number(u.status) === 0 ? "disabled" : "enabled"}</td><td>${esc(u.created_at)}</td><td>${esc(acl.join(", "))}</td><td>${esc(gAcl.join(", "))}</td><td>
        <button class="btn-primary el-button el-button--primary el-button--small" data-user="${u.id}" data-username="${esc(u.username)}" data-act="userManageAcl">权限管理</button>
        <button data-user="${u.id}" data-act="enable">启用</button>
        <button data-user="${u.id}" data-act="disable">禁用</button>
        <button data-user="${u.id}" data-act="delete" class="btn-danger el-button el-button--danger el-button--small">删除</button>
      </td>`;
      tbody.appendChild(tr);
    }
    renderKpis();
  }

  async function loadClients() {
    peersCache = await api("/api/peers").catch(() => []);
    refreshPeerCandidates();
    applyPeerInputHints();
    const tbody = q("#clientsTbl tbody");
    tbody.innerHTML = "";
    for (const c of peersCache) {
      const statusClass = c.online ? "status-online" : "status-offline";
      const statusText = c.online ? "online" : "offline";
      const dbStatus = Number(c.status) === 0 ? "disabled" : "enabled";
      const controlType = c.is_controlled ? "被控端" : "普通设备";
      const nameValue = esc(c.name || "");
      const nameCell = me.role === "admin"
        ? `<div class="peer-name-wrap">
             <input class="peerNameInput" data-peer="${esc(c.id)}" placeholder="设备名称" value="${nameValue}" />
             <button class="btn-primary el-button el-button--primary el-button--small" data-peer="${esc(c.id)}" data-act="peer-save-name">保存</button>
           </div>`
        : (nameValue || "-");
      const actions = me.role === "admin"
        ? `${c.is_controlled
              ? `<button data-peer="${esc(c.id)}" data-act="peer-unmark-controlled">取消被控</button>`
              : `<button class="btn-primary el-button el-button--primary el-button--small" data-peer="${esc(c.id)}" data-act="peer-mark-controlled">标记被控</button>`}
           <button data-peer="${esc(c.id)}" data-act="peer-enable">启用</button>
           <button data-peer="${esc(c.id)}" data-act="peer-disable">禁用</button>
           <button data-peer="${esc(c.id)}" data-act="peer-delete" class="btn-danger el-button el-button--danger el-button--small">删除</button>`
        : "-";
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${esc(c.id)}</td><td>${nameCell}</td><td><span class="status-pill ${statusClass}">${statusText}</span></td><td>${dbStatus}</td><td>${controlType}</td><td>${c.last_seen_secs ?? "-"}</td><td>${esc(c.ip || "-")}</td><td>${esc(c.created_at)}</td><td>${actions}</td>`;
      tbody.appendChild(tr);
    }
    renderKpis();
  }

  function renderDeviceTreeList(devices) {
    if (!devices || !devices.length) return `<div class="subtle tiny">暂无设备</div>`;
    return `<ul class="tree-list">${devices
      .map((d) => {
        const name = String(d.name || "").trim();
        const online = d.online ? "在线" : "离线";
        const status = Number(d.status) === 0 ? "禁用" : "启用";
        const controlled = d.is_controlled ? "被控端" : "普通";
        const title = name
          ? `${esc(name)} <span class="subtle tiny">(${esc(d.id || "")})</span>`
          : esc(d.id || "");
        return `<li>
          <div class="tree-node">
            <span>${title}</span>
            <span class="tree-tag">${online}</span>
            <span class="tree-tag">${status}</span>
            <span class="tree-tag">${controlled}</span>
          </div>
        </li>`;
      })
      .join("")}</ul>`;
  }

  function renderGroupTree(rows) {
    const box = q("#groupTreeBox");
    if (!box) return;
    if (!rows || !rows.length) {
      box.innerHTML = `<div class="subtle">暂无设备组</div>`;
      return;
    }
    box.innerHTML = `<ul class="tree-list">${rows
      .map(
        (g) => `<li>
          <div class="tree-node">
            <strong>${esc(g.name || `Group-${g.id}`)}</strong>
            <span class="tree-tag">组ID: ${esc(g.id)}</span>
            <span class="tree-tag">设备: ${Array.isArray(g.devices) ? g.devices.length : 0}</span>
          </div>
          ${renderDeviceTreeList(g.devices || [])}
        </li>`
      )
      .join("")}</ul>`;
  }

  function renderUserTree(rows) {
    const box = q("#userTreeBox");
    if (!box) return;
    if (!rows || !rows.length) {
      box.innerHTML = `<div class="subtle">暂无关联数据</div>`;
      return;
    }
    box.innerHTML = `<ul class="tree-list">${rows
      .map((u) => {
        const status = Number(u.status) === 0 ? "禁用" : "启用";
        const groups = Array.isArray(u.groups) ? u.groups : [];
        const direct = Array.isArray(u.direct_devices) ? u.direct_devices : [];
        const groupBlocks = groups
          .map(
            (g) => `<li>
              <div class="tree-node">
                <span>${esc(g.name || `Group-${g.id}`)}</span>
                <span class="tree-tag">组ID: ${esc(g.id)}</span>
              </div>
              ${renderDeviceTreeList(g.devices || [])}
            </li>`
          )
          .join("");
        return `<li>
          <div class="tree-node">
            <strong>${esc(u.username || `User-${u.id}`)}</strong>
            <span class="tree-tag">${esc(u.role || "user")}</span>
            <span class="tree-tag">${status}</span>
            <span class="tree-tag">用户ID: ${esc(u.id)}</span>
          </div>
          <ul class="tree-list">
            <li>
              <div class="tree-node"><span>设备组授权</span><span class="tree-tag">${groups.length}</span></div>
              ${groups.length ? `<ul class="tree-list">${groupBlocks}</ul>` : `<div class="subtle tiny">暂无设备组授权</div>`}
            </li>
            <li>
              <div class="tree-node"><span>直接设备授权</span><span class="tree-tag">${direct.length}</span></div>
              ${renderDeviceTreeList(direct)}
            </li>
          </ul>
        </li>`;
      })
      .join("")}</ul>`;
  }

  async function loadGroupTree() {
    const box = q("#groupTreeBox");
    if (!box) return;
    if (me.role !== "admin") {
      box.innerHTML = `<div class="subtle">仅管理员可查看设备组树</div>`;
      return;
    }
    const rows = await api("/api/tree/groups").catch(() => []);
    renderGroupTree(rows);
  }

  async function loadUserTree() {
    const box = q("#userTreeBox");
    if (!box) return;
    const rows = await api("/api/tree/users").catch(() => []);
    renderUserTree(rows);
  }

  async function loadAudits() {
    if (me.role !== "admin") {
      setPanelVisible("auditsPanel", false);
      return;
    }
    setPanelVisible("auditsPanel", true);
    const rows = await api("/api/audits/conn?limit=100").catch(() => []);
    const tbody = q("#auditTbl tbody");
    tbody.innerHTML = "";
    for (const a of rows) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${esc(a.timestamp)}</td><td>${esc(a.from_ip)}</td><td>${esc(a.to_id)}</td><td>${esc(a.to_ip)}</td>`;
      tbody.appendChild(tr);
    }
  }

  async function refreshAll() {
    await loadGroups();
    await loadUsers();
    await loadClients();
    await loadGroupTree();
    await loadUserTree();
    await loadAudits();
  }

  q("#createGroupBtn").onclick = async () => {
    try {
      await api("/api/groups", "POST", { name: q("#newGroup").value.trim() });
      q("#newGroup").value = "";
      await loadGroups();
      await loadUsers();
      await loadGroupTree();
      await loadUserTree();
    } catch (e) {
      alert(e.message);
    }
  };

  q("#groupsTbl").onclick = async (e) => {
    const btn = e.target.closest("button[data-act]");
    if (!btn) return;
    const groupId = btn.getAttribute("data-group");
    const act = btn.getAttribute("data-act");
    try {
      if (act === "groupManagePeers") {
        const groupName = btn.getAttribute("data-group-name") || `Group-${groupId}`;
        await openGroupAclModal(groupId, groupName);
        return;
      } else if (act === "groupDelete") {
        if (!confirm(`确认删除设备组 ${groupId} 吗？`)) return;
        await api(`/api/groups/${groupId}`, "DELETE");
      }
      await reloadAclViews();
    } catch (e) {
      alert(e.message);
    }
  };
  q("#createUserBtn").onclick = async () => {
    try {
      await api("/api/users", "POST", {
        username: q("#newUser").value.trim(),
        password: q("#newPass").value,
        role: q("#newRole").value,
      });
      await loadUsers();
    } catch (e) {
      alert(e.message);
    }
  };

  q("#usersTbl").onclick = async (e) => {
    const btn = e.target.closest("button[data-act]");
    if (!btn) return;
    const userId = btn.getAttribute("data-user");
    const act = btn.getAttribute("data-act");
    try {
      if (act === "userManageAcl") {
        const username = btn.getAttribute("data-username") || `User-${userId}`;
        await openUserAclModal(userId, username);
        return;
      } else if (act === "enable") {
        await api(`/api/users/${userId}/enable`, "POST");
      } else if (act === "disable") {
        await api(`/api/users/${userId}/disable`, "POST");
      } else if (act === "delete") {
        if (!confirm(`确认删除用户 ${userId} 吗？`)) return;
        await api(`/api/users/${userId}`, "DELETE");
      }
      await reloadAclViews();
    } catch (e) {
      alert(e.message);
    }
  };

  q("#clientsTbl").onclick = async (e) => {
    const btn = e.target.closest("button[data-act]");
    if (!btn) return;
    const peerId = btn.getAttribute("data-peer");
    const act = btn.getAttribute("data-act");
    try {
      if (act === "peer-save-name") {
        const input = btn.closest(".peer-name-wrap")?.querySelector("input.peerNameInput");
        const name = (input?.value || "").trim();
        await api(`/api/peers/${encodeURIComponent(peerId)}/name`, "PUT", { name: name || null });
      }
      if (act === "peer-mark-controlled") await api(`/api/peers/${encodeURIComponent(peerId)}/mark-controlled`, "POST");
      if (act === "peer-unmark-controlled") await api(`/api/peers/${encodeURIComponent(peerId)}/unmark-controlled`, "POST");
      if (act === "peer-enable") await api(`/api/peers/${encodeURIComponent(peerId)}/enable`, "POST");
      if (act === "peer-disable") await api(`/api/peers/${encodeURIComponent(peerId)}/disable`, "POST");
      if (act === "peer-delete") {
        if (!confirm(`确认删除设备 ${peerId} 吗？`)) return;
        await api(`/api/peers/${encodeURIComponent(peerId)}`, "DELETE");
      }
      await loadClients();
      await loadGroups();
      await loadUsers();
      await loadGroupTree();
      await loadUserTree();
    } catch (e) {
      alert(e.message);
    }
  };

  q("#refreshAllBtn").onclick = refreshAll;
  q("#refreshAuditsBtn").onclick = loadAudits;

  q("#logoutBtn").onclick = () => {
    localStorage.removeItem("adminToken");
    localStorage.removeItem("adminUser");
    location.href = "/admin/login";
  };

  (async () => {
    if (me.role !== "admin") {
      qa(".admin-only").forEach((x) => x.classList.add("hidden"));
    }
    showPanel("overviewPanel");
    await refreshAll();
    setInterval(async () => {
      await loadClients().catch(() => {});
      if (me.role === "admin") {
        await loadGroupTree().catch(() => {});
      }
      await loadUserTree().catch(() => {});
    }, 5000);
  })();
})();
"##;





































