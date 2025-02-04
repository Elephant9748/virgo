use std::sync::Arc;

use crate::{
    auth::AuthError,
    model::{ParamsAccount, ParamsAccountUsername},
    Account, AppState,
};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use bb8::Pool;
use bb8_postgres::PostgresConnectionManager;
use bcrypt::hash;
use tokio_postgres::NoTls;

pub type ConnectionPool = Pool<PostgresConnectionManager<NoTls>>;

//below using connection pool extractor
//===========================================================================================

pub async fn get_accounts(
    State(shared_state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, AuthError> {
    let conn = shared_state
        .db
        .get()
        .await
        .map_err(|_| AuthError::InternalError)?;

    let row = conn
        .query("select * from accounts", &[])
        .await
        .map_err(|_| AuthError::InternalError)?;

    let result: Vec<Account> = row.into_iter().map(|v| Account::from_row(v)).collect();

    let json_account = serde_json::json!({
        "status": StatusCode::OK.to_string(),
        "body" : &result
    });

    tracing::info!("/acc success!: {:?}", result);
    Ok(Json(json_account))
}

pub async fn insert_accounts(
    State(shared_state): State<Arc<AppState>>,
    Json(params): Json<ParamsAccount>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let conn = shared_state.db.get().await.map_err(internal_error)?;

    //hashing pasword
    let hash_pass = hash(&params.pass, 15).unwrap().to_string();

    let add = conn
        .query(
            "
            insert into accounts (username,pass) values ($1,$2);
            ",
            &[&params.username, &hash_pass],
        )
        .await
        .map_err(internal_error)?;

    let query = conn
        .query(
            "
            select * from accounts where username = $1;
            ",
            &[&params.username],
        )
        .await
        .map_err(internal_error)?;

    let addresult: Vec<Account> = add.into_iter().map(|v| Account::from_row(v)).collect();
    let queryresult: Vec<Account> = query.into_iter().map(|v| Account::from_row(v)).collect();

    let json_account = serde_json::json!({
        "status": StatusCode::OK.to_string(),
        "body" : {
            "insert": (addresult.is_empty()).then(|| "ok" ),
            "select": queryresult,
        }
    });

    tracing::info!("/add/acc success!: {:?}", queryresult);
    Ok(Json(json_account))
}

pub async fn delete_accounts(
    State(shared_state): State<Arc<AppState>>,
    Json(params): Json<ParamsAccountUsername>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let conn = shared_state.db.get().await.map_err(internal_error)?;

    let delete = conn
        .query(
            "
            delete from accounts where username = $1
            ",
            &[&params.username],
        )
        .await
        .map_err(internal_error)?;

    let deleteresult: Vec<Account> = delete.into_iter().map(|v| Account::from_row(v)).collect();

    let json_account = serde_json::json!({
        "status": StatusCode::OK.to_string(),
        "body" : {
            "delete": deleteresult,
        }
    });

    tracing::info!("/add/del success!: {:?}", deleteresult);
    Ok(Json(json_account))
}
//===========================================================================================

/// Utility function for mapping any error into a `500 Internal Server Error`
/// response.
/// anotherway to handle error
fn internal_error<E>(err: E) -> (StatusCode, String)
where
    E: std::error::Error,
{
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

#[allow(dead_code)]
fn header_error<E>(err: E) -> (StatusCode, String)
where
    E: std::error::Error,
{
    (StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE, err.to_string())
}
