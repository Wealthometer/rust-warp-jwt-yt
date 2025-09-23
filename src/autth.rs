use crate::{error::Error, Result, WebResult};
use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use std::fmt;
use warp::{
    filters::header::headers_cloned,
    http::header::{HeaderMap, HeaderValue, AUTHORIZATION},
    reject, Filter, Rejection,
};

const BEARER: &str = "Bearer";
const JWT_SECRET: &[u8] = b"secret";

#[derive(Clone, PartialEq)]
pub enum Role {
    User,
    Admin,
}

impl Role {
    pub fn from_str(role: &str) -> Self {
        match role {
            "Admin" => Role::Admin,
            _ => Role::User,
        }
    }
}

impl ToString for Role {
    fn to_string(&self) -> String {
        match self {
            Role::Admin => "Admin".to_string(),
            Role::User => "User".to_string(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    sub: String,
    role: String,
    exp: usize,
}

pub fn with_auth(role: Role) -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
    headers_cloned()
        .map(move |headers: HeaderMap<HeaderValue>| (role.clone(), headers))
        .and_then(authorize)
}

pub fn create_jwt(uid: &str, role: &Role) -> Result<String> {
    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::seconds(60))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        sub: uid.to_owned(),
        role: role.to_string(),
        exp: expiration as usize,
    };

    let header = Header::new(Algorithm::HS512);
    encode(&header, &claims, &EncodingKey::from_secret(JWT_SECRET))
        .map_err(|_| Error::JWTTokenCreationError)
}

async fn authorize((role, headers): (Role, HeaderMap<HeaderValue>)) -> WebResult<String> {
    match jwt_from_header(&headers) {
        Ok(jwt) => {
            let decoded = decode::<Claims>(
                &jwt,
                &DecodingKey::from_secret(JWT_SECRET),
                &Validation::new(Algorithm::HS512),
            )
            .map_err(|_| reject::custom(Error::JWTTokenError))?;

            if role == Role::Admin && Role::from_str(&decoded.claims.role) != Role::Admin {
                return Err(reject::custom(Error::NoPermissionError));
            }

            Ok(decoded.claims.sub)
        }
        Err(e) => Err(reject::custom(e)),
    }
}

fn jwt_from_header(headers: &HeaderMap<HeaderValue>) -> Result<String> {
    let header = headers
        .get(AUTHORIZATION)
        .ok_or(Error::NoAuthHeaderError)?;

    let auth_header = header.to_str().map_err(|_| Error::InvalidAuthHeaderError)?;

    if !auth_header.starts_with(BEARER) {
        return Err(Error::InvalidAuthHeaderError);
    }

    let token = auth_header.trim_start_matches(BEARER).trim();
    if token.is_empty() {
        return Err(Error::InvalidAuthHeaderError);
    }

    Ok(token.to_string())
}
