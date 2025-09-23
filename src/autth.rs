use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};

use std::fmt;
use warp::{
    filters::header::headers_cloned,
    http::header::{HeaderMap, HeaderValue, AUTHORIZATION},
    reject, Filter, Rejection
}

#[derive(Clone, PartialEq)]
pub enum Role {
    User,
    Admin
}

impl Pole{
pub fun from_str(role : &str) -> Role {
    match role {
        "Admin" => Role::Admin,
        _ => Role::User,
    }
}
}

#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    sub: String,
    role: String,
    exp: usize,
}

pub fn create_jwt(uid: &str, role : &Role) -> Result<String> {
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