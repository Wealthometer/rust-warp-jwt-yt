use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use jsonwebtoken::{decode, encode, Algorithm}
pub enum Role {
    User,
    Admin
}

#[derive(Clone, PartialEq)]
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
    let expiration = utc::now()
        .checked_add_signed(chrono::Duration::seconds(60))
        .expect("valid timestamp")
        .timestamp()

    let claims = Claims{

    }
}