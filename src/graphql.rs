use async_graphql::{Context, Error, Object};
use bcrypt::{hash, verify};
use jsonwebtoken::{encode, Header};
use uuid::Uuid;

use crate::{auth::Claims, model::Account, query::ConnectionPool, KEYS};

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
        Ok(graphql_data)
    }
    async fn greet(&self, ctx: &Context<'_>) -> String {
        let head = ctx.http_header_contains("Authorization");
        tracing::debug!("{:?}", head);

        String::from("OK".to_string())
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
