use async_graphql::{Context, Error, Guard, Object};
use bcrypt::hash;
use uuid::Uuid;

use crate::{model::Account, query::ConnectionPool};

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
}

pub struct MutationRoot;

#[Object]
impl MutationRoot {
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

// Field guard
#[derive(Eq, PartialEq, Copy, Clone)]
#[allow(dead_code)]
pub enum Role {
    Root,
    Rigel,
}

pub struct RoleGuard {
    role: Role,
}

#[allow(dead_code)]
impl RoleGuard {
    fn new(role: Role) -> Self {
        Self { role }
    }
}

impl Guard for RoleGuard {
    async fn check(&self, ctx: &Context<'_>) -> Result<(), Error> {
        if ctx.data_opt::<Role>() == Some(&self.role) {
            Ok(())
        } else {
            Err(Error::new("Doesnt have any role!"))
        }
    }
}
