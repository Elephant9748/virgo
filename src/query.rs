use crate::{
    auth::AuthError,
    model::{ParamsAccount, ParamsAccountUsername},
    Account,
};
use axum::{
    extract::{FromRef, FromRequestParts, State},
    http::{request::Parts, StatusCode},
    response::IntoResponse,
    Json,
};
use bb8::{Pool, PooledConnection};
use bb8_postgres::PostgresConnectionManager;
use bcrypt::hash;
use tokio_postgres::NoTls;

// we can also write a custom extractor that grabs a connection from the pool
// which setup is appropriate depends on your application
pub struct DbConnection(PooledConnection<'static, PostgresConnectionManager<NoTls>>);

impl<S> FromRequestParts<S> for DbConnection
where
    ConnectionPool: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let pool = ConnectionPool::from_ref(state);

        let conn = pool
            .get_owned()
            .await
            .map_err(|_| AuthError::InternalError)?;

        Ok(Self(conn))
    }
}

pub async fn get_accounts_extractor(
    DbConnection(conn): DbConnection,
) -> Result<impl IntoResponse, AuthError> {
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

pub async fn insert_accounts_extractor(
    DbConnection(conn): DbConnection,
    Json(params): Json<ParamsAccount>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
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

pub async fn delete_accounts_extractor(
    DbConnection(conn): DbConnection,
    Json(params): Json<ParamsAccountUsername>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
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

//below using connection pool extractor
//===========================================================================================
pub type ConnectionPool = Pool<PostgresConnectionManager<NoTls>>;

pub async fn get_accounts(
    State(pool): State<ConnectionPool>,
) -> Result<impl IntoResponse, AuthError> {
    let conn = pool.get().await.map_err(|_| AuthError::InternalError)?;

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
    State(pool): State<ConnectionPool>,
    Json(params): Json<ParamsAccount>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let conn = pool.get().await.map_err(internal_error)?;

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
    State(pool): State<ConnectionPool>,
    Json(params): Json<ParamsAccountUsername>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let conn = pool.get().await.map_err(internal_error)?;

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
