use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json, RequestPartsExt,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use std::fmt::Display;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::KEYS;

pub struct Keys {
    pub encod: EncodingKey,
    pub decod: DecodingKey,
}

impl Keys {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            encod: EncodingKey::from_secret(secret),
            decod: DecodingKey::from_secret(secret),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AuthBody {
    access_token: String,
    token_type: String,
}

impl AuthBody {
    fn new(access_token: String) -> Self {
        Self {
            access_token,
            token_type: "Bearer".to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AuthPayload {
    client_id: String,
    client_secret: String,
}

#[derive(Debug)]
pub enum AuthError {
    WrongCredentials,
    MissingCredentials,
    TokenCreation,
    InvalidToken,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::WrongCredentials => (StatusCode::UNAUTHORIZED, "Wrong credentials"),
            AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, "Missing credentials"),
            AuthError::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "Token creation error"),
            AuthError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid token"),
        };
        let body = Json(json!({
            "error": error_message,
        }));
        (status, body).into_response()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    authorization: bool,
    data: String,
    exp: usize,
}

impl Display for Claims {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "authorization: {} \n data: {}",
            self.authorization, self.data
        )
    }
}

impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::InvalidToken)?;
        // Decode the user data
        let token_data = decode::<Claims>(bearer.token(), &KEYS.decod, &Validation::default())
            .map_err(|_| AuthError::InvalidToken)?;

        println!("{:?}", token_data);

        Ok(token_data.claims)
    }
}

pub async fn authorize_login(
    Json(payload): Json<AuthPayload>,
) -> Result<Json<AuthBody>, AuthError> {
    if payload.client_id.is_empty() || payload.client_secret.is_empty() {
        return Err(AuthError::MissingCredentials);
    }
    if payload.client_id != "virgo" || payload.client_secret != "pass" {
        return Err(AuthError::WrongCredentials);
    }

    let claims = Claims {
        authorization: true,
        data: "your can access your data now!".to_owned(),
        exp: 2000000000,
    };

    // create token
    let jwt_token =
        encode(&Header::default(), &claims, &KEYS.encod).map_err(|_| AuthError::TokenCreation)?;

    // send auth token
    Ok(Json(AuthBody::new(jwt_token)))
}

pub async fn protected(claims: Claims) -> Result<impl IntoResponse, AuthError> {
    let response = serde_json::json!({
        "message": "Welcome to protected area :)",
        "body": claims,
    });

    Ok(Json(response))
}
