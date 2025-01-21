use serde::{Deserialize, Serialize};
use tokio_postgres::Row;
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct Account {
    pub account_id: Uuid,
    pub username: String,
    pub pass: String,
}

impl Account {
    pub fn new(col: Row) -> Self {
        Self {
            account_id: col.get("account_id"),
            username: col.get("username"),
            pass: col.get("pass"),
        }
    }
}
