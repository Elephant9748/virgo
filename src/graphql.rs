use std::sync::Arc;

use async_graphql::{
    http::{playground_source, GraphQLPlaygroundConfig, GraphiQLSource},
    Context, EmptySubscription, Error, Object, Schema,
};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::{
    extract::State,
    http::HeaderMap,
    response::{self, Html, IntoResponse, Response},
};
use bcrypt::{hash, verify};
use jsonwebtoken::{encode, Header};
use uuid::Uuid;

use crate::{
    auth::{AuthError, Claims},
    model::Account,
    query::ConnectionPool,
    AppState, KEYS,
};

#[Object]
impl Account {
    async fn uuid(&self) -> &Uuid {
        &self.account_id
    }
    async fn username(&self) -> &str {
        &self.username
    }
    async fn pass(&self) -> &str {
        &self.pass
    }
}

pub struct QueryRoot;

#[Object]
impl QueryRoot {
    async fn accounts(&self, ctx: &Context<'_>) -> Result<Vec<Account>, Error> {
        let conn = ctx.data_unchecked::<ConnectionPool>();
        let db = conn.get().await.unwrap();
        let row = db.query("select * from accounts", &[]).await.unwrap();
        let graphql_data: Vec<Account> = row.into_iter().map(|v| Account::from_row(v)).collect();
        if graphql_data.is_empty() {
            return Err(Error::new("graphql_data empty maybe db connections error!"));
        }
        tracing::info!(
            "get accounts graphql - {:?}",
            ctx.data::<ReqHeaders>().unwrap().ua()
        );
        Ok(graphql_data)
    }
    async fn greet(&self, ctx: &Context<'_>) -> Result<String, Error> {
        tracing::info!(
            "get accounts graphql - {:?}",
            ctx.data::<ReqHeaders>().unwrap().ua()
        );
        Ok(ctx
            .data::<ReqHeaders>()
            .unwrap()
            .authorization()
            .to_string())
    }
}

pub struct MutationRoot;

#[Object]
impl MutationRoot {
    async fn login(
        &self,
        ctx: &Context<'_>,
        username: String,
        pass: String,
    ) -> Result<String, Error> {
        let head = ctx.http_header_contains("Authorization");
        tracing::debug!("{:?}", head);
        let conn = ctx.data_unchecked::<ConnectionPool>();
        let db = conn.get().await.unwrap();
        let row = db
            .query("select * from accounts where username = $1", &[&username])
            .await
            .unwrap();
        let graphql_data: Vec<Account> = row.into_iter().map(|x| Account::from_row(x)).collect();

        if username.is_empty() || pass.is_empty() {
            return Err(Error::new("username or pass is empty !"));
        }

        let hash_verify_pass = verify(&pass, graphql_data[0].pass.as_str()).unwrap();

        if username != graphql_data[0].username || hash_verify_pass == false {
            return Err(Error::new("wrong credentials !"));
        }

        let claims = Claims {
            authorization: true,
            data: "your can access your data now!".to_owned(),
            // !todo better exp time
            exp: 2000000000,
            // exp: 2000000,
        };

        //create token
        let jwt_token = encode(&Header::default(), &claims, &KEYS.encod).unwrap();

        tracing::debug!("{}-token: {:?}", username, jwt_token);

        Ok(jwt_token.into())
    }

    async fn insert_accounts(
        &self,
        ctx: &Context<'_>,
        username: String,
        pass: String,
    ) -> Result<Vec<Account>, Error> {
        let conn = ctx.data_unchecked::<ConnectionPool>();
        let db = conn.get().await.unwrap();

        //hash_password
        let hash_pass = hash(&pass, 15).unwrap().to_string();

        let row = db
            .query(
                "insert into accounts (username, pass) values ($1,$2)",
                &[&username, &hash_pass],
            )
            .await
            .unwrap();
        if !row.is_empty() {
            return Err(Error::new("graphql_data empty maybe db connections error!"));
        }
        let get_insert = db
            .query("select * from accounts where username = $1", &[&username])
            .await
            .unwrap();
        let graphql_data: Vec<Account> = get_insert
            .into_iter()
            .map(|x| Account::from_row(x))
            .collect();

        tracing::debug!("{:?}", graphql_data);
        Ok(graphql_data)
    }

    async fn delete_accounts(&self, ctx: &Context<'_>, username: String) -> Result<bool, Error> {
        let conn = ctx.data_unchecked::<ConnectionPool>();
        let db = conn.get().await.unwrap();

        let row = db
            .query("delete from accounts where username = $1", &[&username])
            .await
            .unwrap();
        if !row.is_empty() {
            return Err(Error::new("graphql_data empty maybe db connections error!"));
        }

        let graphql_data: Vec<Account> = row.into_iter().map(|x| Account::from_row(x)).collect();
        if !graphql_data.is_empty() {
            return Err(Error::new("graphql_data empty maybe db connections error!"));
        }

        tracing::debug!("{:?}", graphql_data);
        Ok(true)
    }
}

// graphql handler
pub async fn graphqlhandler() -> impl IntoResponse {
    response::Html(
        GraphiQLSource::build()
            .endpoint("/graphql")
            .subscription_endpoint("/ws")
            .finish(),
    )
}

//graphql handler grap headers values
pub async fn graphqlhandler_include_headers(
    State(shared_state): State<Arc<AppState>>,
    headers: HeaderMap,
    req: GraphQLRequest,
) -> Result<Response, AuthError> {
    let get_headers = get_headers_to_graphql(&headers);
    if get_headers.is_none() {
        return Err(AuthError::InvalidRequestHeader);
    }

    let resp_gql = shared_state
        .schema
        .execute(req.into_inner().data(get_headers.unwrap()))
        .await;

    tracing::debug!(
        "graphqlhandler_include_headers: {:?}",
        get_headers_to_graphql(&headers)
    );

    let response = GraphQLResponse::from(resp_gql).into_response();
    Ok(response)
}

pub type SchemaVirgo = Schema<QueryRoot, MutationRoot, EmptySubscription>;

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct ReqHeaders {
    pub ua: String,
    pub authorization: String,
}

#[allow(dead_code)]
impl ReqHeaders {
    pub fn new(ua: String, authorization: String) -> Self {
        Self { ua, authorization }
    }
    pub fn ua(&self) -> &str {
        &self.ua
    }
    pub fn authorization(&self) -> &str {
        &self.authorization
    }
}

#[allow(dead_code)]
pub async fn graphql_playground() -> impl IntoResponse {
    Html(playground_source(
        GraphQLPlaygroundConfig::new("/graphql").subscription_endpoint("/ws"),
    ))
}

pub fn get_headers_to_graphql(headers: &HeaderMap) -> Option<ReqHeaders> {
    let ua = headers.get("User-Agent").to_owned();
    let authorization = headers.get("Authorization").to_owned();

    if ua.is_none() || authorization.is_none() {
        return None;
    }

    Some(ReqHeaders {
        ua: format!("{:?}", ua.unwrap()).to_string(),
        authorization: format!("{:?}", authorization.unwrap()).to_string(),
    })
}
