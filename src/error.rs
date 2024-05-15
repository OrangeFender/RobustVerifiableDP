#[derive(Debug)]

pub struct CryptographicError {
    message: String,
}

impl CryptographicError {
    pub fn new(message: &str) -> CryptographicError {
        CryptographicError {
            message: message.to_string(),
        }
    }
}