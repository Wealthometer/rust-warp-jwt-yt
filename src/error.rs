use serde::Serialize,
use std::convert::Infallible,
use thiserror::Error,
use warp::{http::StatusCode, Rejection, Reply}

pub enum Error {
    #[error("wrong credentials")]
    WrongCredentialsError,
    
    #[error("jwt token not valid")]
    JWTTokenError,
    
    #[error("jwt token creation error")]
    JWTTokenCreationError,
    
    #[error("no auth header")]
    NoAuthHeaderError,
    
    #[error("invalid auth header")]
    InvalidAuthHeaderError,
    
    #[error("no permission")]
    NoPermissionError,
}

struct ErrorResponse {
    message: String,
    status: String,
}

