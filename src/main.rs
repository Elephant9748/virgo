mod auth;
mod graphql;
mod model;
mod query;

use async_graphql::{EmptySubscription, Schema};
use async_graphql_axum::GraphQLSubscription;
use axum::{
    http::Method,
    middleware,
    routing::{delete, get, post},
    Router,
};
use bb8::Pool;
use bb8_postgres::PostgresConnectionManager;
use graphql::{graphqlhandler_include_headers, SchemaVirgo};
use query::ConnectionPool;
use std::{
    env::var,
    sync::{Arc, LazyLock},
};
use tokio_postgres::NoTls;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::{
    auth::{auth_middleware, create_token, protected, sign_in, sign_in_using_path, Keys},
    graphql::{graphqlhandler, MutationRoot, QueryRoot},
    model::Account,
    query::{delete_accounts, get_accounts, insert_accounts},
};

// secret keys jwt
pub static KEYS: LazyLock<Keys> = LazyLock::new(|| {
    let secret_key = var("SECRET_KEY").expect("SECRET_KEY must be set");
    Keys::new(secret_key.as_bytes())
});

// global state
#[derive(Clone)]
pub struct AppState {
    pub db: ConnectionPool,
    pub schema: SchemaVirgo,
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
    let schema = Schema::build(QueryRoot, MutationRoot, EmptySubscription)
        .data(pool.clone())
        .finish();

    // shared_state
    let shared_state = Arc::new(AppState {
        db: pool.clone(),
        schema: schema.clone(),
    });

    // cors
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::DELETE])
        .allow_origin(Any);

    let rest_router = Router::new()
        .route(
            "/accounts",
            get(get_accounts)
                .post(insert_accounts)
                .delete(delete_accounts),
        )
        .route("/acc/insert", post(insert_accounts))
        .route("/acc/delete", delete(delete_accounts))
        .route("/locker", get(protected))
        .layer(middleware::from_fn(auth_middleware));

    let graphql_router = Router::new()
        .route("/createtoken", post(create_token))
        .route("/signin", post(sign_in))
        .route("/signin/{username}/{pass}", get(sign_in_using_path))
        // =======================================
        // .route(
        //     "/graphql",
        //     get(graphqlhandler).post_service(GraphQL::new(schema.clone())),
        // )
        .route(
            "/graphql",
            get(graphqlhandler).post(graphqlhandler_include_headers),
        )
        // .layer(middleware::from_fn_with_state(
        //     // shared_state.clone(),
        //     ctx.clone(),
        //     state_fn_as_middleware,
        // ))
        .route_service("/ws", GraphQLSubscription::new(schema.clone()));
    // .layer(Extension(schema.clone()));

    // build our application with some routes
    let app = Router::new()
        .merge(rest_router)
        .merge(graphql_router)
        .layer(cors)
        .with_state(shared_state);

    // run it
    let listener = tokio::net::TcpListener::bind("127.0.0.1:7000")
        .await
        .unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
