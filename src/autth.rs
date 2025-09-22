

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

struct Claims {

}

pub fn create_jwt(uid: &str, role : &Role) -> Result<String> {
    let expiration = utc::now()
        .checked_add_signed
}