use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

pub fn to_note_account(row: &Account) -> AccountResponse {
    AccountResponse {
        account_id: row.account_id.to_owned(),
        username: row.username.to_owned(),
        pass: row.pass.to_owned(),
    }
}
