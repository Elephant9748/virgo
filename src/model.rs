use axum::body::Bytes;
use serde::{Deserialize, Serialize};
use tokio_postgres::Row;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct Account {
    pub account_id: Uuid,
    pub username: String,
    pub pass: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ParamsAccount {
    pub username: String,
    pub pass: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ParamsAccountWithUA {
    pub username: String,
    pub pass: String,
    pub useragent: Bytes,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ParamsAccountUsername {
    pub username: String,
}

impl Account {
    pub fn from_row(col: Row) -> Self {
        Self {
            account_id: col.get("account_id"),
            username: col.get("username"),
            pass: col.get("pass"),
        }
    }
}
