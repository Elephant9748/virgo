mod auth;
mod model;
mod query;

use async_graphql::{
    connection::EmptyFields, http::GraphiQLSource, EmptyMutation, EmptySubscription, Schema,
};
use async_graphql_axum::{GraphQL, GraphQLSubscription};
use axum::{
    http::Method,
    middleware,
    response::{self, IntoResponse},
    routing::{delete, get, post},
    Router,
};
use bb8::Pool;
use bb8_postgres::PostgresConnectionManager;
use query::{delete_accounts_extractor, get_accounts_extractor, insert_accounts_extractor};
use std::{env::var, sync::LazyLock};
use tokio_postgres::NoTls;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::{
    auth::{auth_middleware, create_token, protected, sign_in, sign_in_using_path, Keys},
    model::Account,
    query::{delete_accounts, get_accounts, insert_accounts},
};

// secret keys jwt
pub static KEYS: LazyLock<Keys> = LazyLock::new(|| {
    let secret_key = var("SECRET_KEY").expect("SECRET_KEY must be set");
    Keys::new(secret_key.as_bytes())
});

// graphql handler
pub async fn graphqlhandler() -> impl IntoResponse {
    response::Html(
        GraphiQLSource::build()
            .endpoint("/graphql")
            .subscription_endpoint("/ws")
            .finish(),
    )
}

//shared_state
#[derive(Clone)]
pub struct AppState {
    pub useragent: String,
}

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

    //graphql schema
    // doesnt have scheme properly yet
    let schema = Schema::build(EmptyFields, EmptyMutation, EmptySubscription).finish();

    // cors
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::DELETE])
        .allow_origin(Any);

    // build our application with some routes
    let app = Router::new()
        // using connection pool extractor
        // =======================================
        .route(
            "/",
            get(get_accounts_extractor)
                .post(insert_accounts_extractor)
                .delete(delete_accounts_extractor),
        )
        .route("/acc/add", post(insert_accounts))
        .route("/acc/del", delete(delete_accounts))
        // =======================================
        //
        // using connection extractor
        // ---------------------------------------
        .route(
            "/accounts",
            get(get_accounts)
                .post(insert_accounts)
                .delete(delete_accounts),
        )
        .route("/acc/insert", post(insert_accounts))
        .route("/acc/delete", delete(delete_accounts))
        // ---------------------------------------
        .route("/locker", get(protected))
        .layer(middleware::from_fn(auth_middleware))
        // using connection pool extractor
        // =======================================
        .route("/createtoken", post(create_token))
        .route("/signin", post(sign_in))
        .route("/signin/{username}/{pass}", get(sign_in_using_path))
        // =======================================
        .route(
            "/graphql",
            get(graphqlhandler).post_service(GraphQL::new(schema.clone())),
        )
        .route_service("/ws", GraphQLSubscription::new(schema))
        .layer(cors)
        .with_state(pool);

    // run it
    let listener = tokio::net::TcpListener::bind("127.0.0.1:7000")
        .await
        .unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
