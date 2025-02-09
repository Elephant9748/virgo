use axum::{
    extract::{FromRequestParts, Path, Request, State},
    http::{request::Parts, HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Extension, Json, RequestPartsExt,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use bcrypt::verify;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use std::{fmt::Display, sync::Arc};

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    model::{Account, ParamsAccount},
    AppState, KEYS,
};

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

#[derive(Debug, Deserialize, Serialize)]
pub struct AuthPayload {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug)]
pub enum AuthError {
    WrongCredentials,
    MissingCredentials,
    TokenCreation,
    InvalidToken,
    InternalError,
    MissingToken,
    InvalidRequestHeader,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::WrongCredentials => (StatusCode::UNAUTHORIZED, "Wrong credentials"),
            AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, "Missing credentials"),
            AuthError::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "Token creation error"),
            AuthError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid token"),
            AuthError::InternalError => (StatusCode::BAD_REQUEST, "Bad Request"),
            AuthError::MissingToken => (StatusCode::BAD_REQUEST, "Missing Token"),
            AuthError::InvalidRequestHeader => (
                StatusCode::BAD_REQUEST,
                "Missing Headers or Doesnt Have Authorization Headers!",
            ),
        };
        let body = Json(json!({
            "message": error_message,
            "error": status.to_string(),
        }));
        (status, body).into_response()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Claims {
    pub authorization: bool,
    pub data: String,
    pub exp: usize,
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

// auth jwt & access db from claims
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

        // tracing::info!("{:?}", token_data);

        Ok(token_data.claims)
    }
}

// todo! set proper claims, exp
pub async fn sign_in_using_path(
    Path((username, pass)): Path<(String, String)>,
    State(shared_state): State<Arc<AppState>>,
    req: Request,
) -> Result<Json<AuthBody>, AuthError> {
    tracing::debug!("req: {:?}", req);
    let conn = shared_state
        .db
        .get()
        .await
        .map_err(|_| AuthError::InternalError)?;
    let query = conn
        .query("select * from accounts where username = $1", &[&username])
        .await
        .map_err(|_| AuthError::InternalError)?;
    let account_from_query: Vec<Account> =
        query.into_iter().map(|a| Account::from_row(a)).collect();

    if account_from_query.is_empty() {
        tracing::error!(
            "User: {} signin using path failed with error {:?}!",
            username,
            AuthError::InternalError
        );
        return Err(AuthError::InternalError);
    }

    if username.is_empty() || pass.is_empty() {
        tracing::error!(
            "User: {} signin using path failed with error {:?}!",
            username,
            AuthError::MissingCredentials
        );
        return Err(AuthError::MissingCredentials);
    }

    //verify hashing password
    let hash_pass_verify = verify(&pass, account_from_query[0].pass.as_str()).unwrap();

    if username != account_from_query[0].username || hash_pass_verify == false {
        tracing::error!(
            "User: {} signin using path failed with error {:?}!",
            username,
            AuthError::WrongCredentials
        );
        return Err(AuthError::WrongCredentials);
    }

    let claims = Claims {
        authorization: true,
        data: "your can access your data now!".to_owned(),
        // !todo better exp time
        exp: 2000000000,
        // exp: 2000000,
    };

    // create token
    let jwt_token =
        encode(&Header::default(), &claims, &KEYS.encod).map_err(|_| AuthError::TokenCreation)?;

    let useragent = req
        .headers()
        .get("User-Agent")
        .unwrap()
        .to_str()
        .unwrap_or_default();

    tracing::info!(
        "{} signin using path success! useragent: {}",
        username,
        useragent
    );

    // send auth token
    Ok(Json(AuthBody::new(jwt_token)))
}

// todo!()  set proper claims, exp
pub async fn sign_in(
    headers: HeaderMap,
    State(shared_state): State<Arc<AppState>>,
    Json(payload): Json<ParamsAccount>,
) -> Result<impl IntoResponse, AuthError> {
    let conn = shared_state
        .db
        .get()
        .await
        .map_err(|_| AuthError::InternalError)?;
    let query = conn
        .query(
            "select * from accounts where username = $1",
            &[&payload.username],
        )
        .await
        .map_err(|_| AuthError::InternalError)?;
    let account_from_query: Vec<Account> =
        query.into_iter().map(|a| Account::from_row(a)).collect();

    if account_from_query.is_empty() {
        tracing::error!(
            "User: {} signin using path failed with error {:?}!",
            payload.username,
            AuthError::InternalError
        );
        return Err(AuthError::InternalError);
    }

    if payload.username.is_empty() || payload.pass.is_empty() {
        tracing::error!(
            "User: {} signin using path failed with error {:?}!",
            payload.username,
            AuthError::MissingCredentials
        );
        return Err(AuthError::MissingCredentials);
    }
    //verify hashing password
    let hash_pass_verify = verify(&payload.pass, account_from_query[0].pass.as_str()).unwrap();

    if payload.username != account_from_query[0].username || hash_pass_verify == false {
        tracing::error!(
            "User: {} signin using path failed with error {:?}!",
            payload.username,
            AuthError::WrongCredentials
        );
        return Err(AuthError::WrongCredentials);
    }

    let claims = Claims {
        authorization: true,
        data: "your can access your data now!".to_owned(),
        // !todo better exp time
        exp: 2000000000,
        // exp: 2000000,
    };

    // create token
    let jwt_token =
        encode(&Header::default(), &claims, &KEYS.encod).map_err(|_| AuthError::TokenCreation)?;

    tracing::info!(
        "{} signin using path success! useragent: {:?}",
        payload.username,
        headers.get("User-Agent").to_owned().unwrap()
    );

    // send auth token
    Ok(Json(AuthBody::new(jwt_token)))
}

//middleware
//-----------------------------------------------------------------------------------------------------

// require jwt token as middleware
pub async fn auth_middleware(req: Request, next: Next) -> Result<impl IntoResponse, AuthError> {
    let auth_header = req.headers().get("Authorization");
    if let Some(auth_header) = auth_header {
        let token = auth_header.to_str().unwrap_or_default();
        let token = token.strip_prefix("Bearer ").unwrap_or_default();
        let token_data = decode::<Claims>(token, &KEYS.decod, &Validation::default())
            .map_err(|_| AuthError::InvalidToken)?;
        tracing::info!("{:?}", token_data);
        // Pass the request to the next handler
        Ok(next.run(req).await)
    } else {
        // Return an error response if the token is missing
        Err(AuthError::MissingToken)
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct CtxHeaders {
    pub ua: String,
}

#[allow(dead_code)]
impl CtxHeaders {
    pub fn new(uagent: String) -> Self {
        Self { ua: uagent }
    }
    pub fn ua(&self) -> &str {
        &self.ua
    }
}

#[allow(dead_code)]
pub async fn state_fn_as_middleware(mut req: Request, next: Next) -> Response {
    let ctx = CtxHeaders::new("useragent".into());
    req.extensions_mut().insert(ctx);
    tracing::debug!("state_fn_as_middleware: {:?}", req);
    next.run(req).await
}
//-----------------------------------------------------------------------------------------------------

// todo! need to grap from db
pub async fn create_token(Json(payload): Json<AuthPayload>) -> Result<Json<AuthBody>, AuthError> {
    if payload.client_id.is_empty() || payload.client_secret.is_empty() {
        return Err(AuthError::MissingCredentials);
    }
    if payload.client_id != "virgo" || payload.client_secret != "pass" {
        return Err(AuthError::WrongCredentials);
    }

    let claims = Claims {
        authorization: true,
        data: "your can access your data now!".to_owned(),
        // !todo better exp time
        exp: 2000000000,
        // exp: 2000000,
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

#[allow(dead_code)]
pub async fn user_token(Extension(authpayload): Extension<AuthPayload>) -> impl IntoResponse {
    Json(AuthPayload {
        client_id: authpayload.client_id,
        client_secret: authpayload.client_secret,
    })
}
