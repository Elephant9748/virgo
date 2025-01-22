use std::env::var;

use axum::{
    routing::{delete, get, post},
    Router,
};
use bb8::Pool;
use bb8_postgres::PostgresConnectionManager;
use tokio_postgres::NoTls;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod model;
mod query;
use crate::{
    model::Account,
    query::{delete_accounts, get_accounts, insert_accounts},
};

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

    let config = format!(
        "hostaddr={} port={} user={} password={} dbname={}",
        var("POSTGRES_HOST").unwrap(),
        var("POSTGRES_PORT").unwrap(),
        var("POSTGRES_USER").unwrap(),
        var("POSTGRES_PASSWORD").unwrap(),
        var("POSTGRES_DB").unwrap(),
    );

    // set up connection pool
    let manager = PostgresConnectionManager::new_from_stringlike(config, NoTls).unwrap();
    let pool = Pool::builder().build(manager).await.unwrap();

    // build our application with some routes
    let app = Router::new()
        .route(
            "/",
            get(get_accounts)
                .post(insert_accounts)
                .delete(delete_accounts),
        )
        .route("/acc/add", post(insert_accounts))
        .route("/acc/del", delete(delete_accounts))
        .with_state(pool);

    // run it
    let listener = tokio::net::TcpListener::bind("127.0.0.1:7000")
        .await
        .unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
