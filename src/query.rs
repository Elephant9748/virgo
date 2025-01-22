use crate::{
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
use tokio_postgres::NoTls;

pub type ConnectionPool = Pool<PostgresConnectionManager<NoTls>>;

pub async fn get_accounts(
    State(pool): State<ConnectionPool>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let conn = pool.get().await.map_err(internal_error)?;

    let row = conn
        .query("select * from accounts", &[])
        .await
        .map_err(internal_error)?;

    let result: Vec<Account> = row.into_iter().map(|v| Account::from_row(v)).collect();

    let accounts_json = serde_json::to_string_pretty(&result);

    println!("{:?}", accounts_json.unwrap());

    let json_account = serde_json::json!({
        "status": "tbd",
        "header": "tbd",
        "body" : &result
    });

    Ok(Json(json_account))
}

pub async fn insert_accounts(
    State(pool): State<ConnectionPool>,
    Json(params): Json<ParamsAccount>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let conn = pool.get().await.map_err(internal_error)?;

    let add = conn
        .query(
            "
            insert into accounts (username,pass) values ($1,$2);
            ",
            &[&params.username, &params.pass],
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

    let accounts_json = serde_json::to_string_pretty(&queryresult);

    println!("{:?}", &params);
    println!("{:?}", accounts_json.unwrap());

    let json_account = serde_json::json!({
        "status": "tbd",
        "header": "tbd",
        "body" : {
            "insert": (addresult.is_empty()).then(|| "ok" ),
            "select": queryresult,
        }
    });

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

    let accounts_json = serde_json::to_string_pretty(&deleteresult);

    println!("{:?}", &params);
    println!("{:?}", accounts_json.unwrap());

    let json_account = serde_json::json!({
        "status": "tbd",
        "header": "tbd",
        "body" : {
            "delete": deleteresult,
        }
    });

    Ok(Json(json_account))
}

// we can also write a custom extractor that grabs a connection from the pool
// which setup is appropriate depends on your application
pub struct DatabaseConnection(PooledConnection<'static, PostgresConnectionManager<NoTls>>);

impl<S> FromRequestParts<S> for DatabaseConnection
where
    ConnectionPool: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let pool = ConnectionPool::from_ref(state);

        let conn = pool.get_owned().await.map_err(internal_error)?;

        Ok(Self(conn))
    }
}

#[allow(dead_code)]
pub async fn using_connection_extractor(
    DatabaseConnection(conn): DatabaseConnection,
) -> Result<String, (StatusCode, String)> {
    let row = conn
        .query_one("select 1 + 1", &[])
        .await
        .map_err(internal_error)?;
    let two: i32 = row.try_get(0).map_err(internal_error)?;

    Ok(two.to_string())
}

/// Utility function for mapping any error into a `500 Internal Server Error`
/// response.
fn internal_error<E>(err: E) -> (StatusCode, String)
where
    E: std::error::Error,
{
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}
