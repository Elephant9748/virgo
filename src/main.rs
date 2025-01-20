//! ```not_rust
//! curl 127.0.0.1:7000
//! curl -X POST 127.0.0.1:7000
//! ```

use axum::{
    extract::{FromRef, FromRequestParts, Query, State},
    http::{request::Parts, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

use std::{env::var, sync::Arc, time::Duration};

#[tokio::main]
async fn main() {
    //watch out for Vulnerability dotenvy
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("{}=debug", env!("CARGO_CRATE_NAME")).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // .env
    let db_connect_options = PgConnectOptions::new()
        .host(&var("POSTGRES_HOST").unwrap())
        .port(
            var("POSTGRES_PORT")
                .unwrap()
                .to_string()
                .parse::<u16>()
                .unwrap(),
        )
        .username(&var("POSTGRES_USER").unwrap())
        .database(&var("POSTGRES_DB").unwrap())
        .password(&var("POSTGRES_PASSWORD").unwrap())
        .to_owned();

    // set up connection pool
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(3))
        .connect_with(db_connect_options)
        .await
        .expect("can't connect to database");

    // build our application with some routes
    let app = Router::new()
        .route(
            "/",
            get(using_connection_pool_extractor).post(using_connection_extractor),
        )
        .with_state(pool);

    // run it with hyper
    let listener = TcpListener::bind("127.0.0.1:7000").await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

#[derive(Debug, Deserialize, Serialize, sqlx::FromRow)]
pub struct Account {
    pub account_id: Uuid,
    pub username: String,
    pub pass: String,
}
#[derive(Debug, Deserialize, Serialize)]
pub struct AccountResponse {
    pub account_id: Uuid,
    pub username: String,
    pub pass: String,
}

fn to_note_account(row: &Account) -> AccountResponse {
    AccountResponse {
        account_id: row.account_id.to_owned(),
        username: row.username.to_owned(),
        pass: row.pass.to_owned(),
    }
}

// we can extract the connection pool with `State`
async fn using_connection_pool_extractor(
    State(pool): State<PgPool>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let row = sqlx::query_as::<_, Account>(r#"SELECT * FROM accounts"#)
        .fetch_all(&pool)
        .await
        .map_err(internal_error)?;

    let accounts = row
        .iter()
        .map(|x| to_note_account(&x))
        .collect::<Vec<AccountResponse>>();

    println!("{:?}", &row);

    let json_response = serde_json::json!({
        "status": "200",
        "header": "X-Custom-Foo Bar",
        "Body": accounts
    });

    Ok(Json(json_response))
}

// we can also write a custom extractor that grabs a connection from the pool
// which setup is appropriate depends on your application
struct DatabaseConnection(sqlx::pool::PoolConnection<sqlx::Postgres>);

impl<S> FromRequestParts<S> for DatabaseConnection
where
    PgPool: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let pool = PgPool::from_ref(state);

        let conn = pool.acquire().await.map_err(internal_error)?;

        Ok(Self(conn))
    }
}

async fn using_connection_extractor(
    DatabaseConnection(mut conn): DatabaseConnection,
) -> Result<String, (StatusCode, String)> {
    sqlx::query_scalar("select 'hello world from pg'")
        .fetch_one(&mut *conn)
        .await
        .map_err(internal_error)
}

/// Utility function for mapping any error into a `500 Internal Server Error`
/// response.
fn internal_error<E>(err: E) -> (StatusCode, String)
where
    E: std::error::Error,
{
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}
