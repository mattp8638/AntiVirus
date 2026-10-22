#[derive(Debug)]
pub struct ValidationLimits {
    pub max_command_id_len: usize,
    pub max_payload_len: usize,
    pub max_stream_len: usize,
}

impl ValidationLimits {
    pub fn default_limits() -> Self {
        Self {
            max_command_id_len: 128,
            max_payload_len: 8192,
            max_stream_len: 64,
        }
    }
}

pub fn validate_bounded_string(value: &str, max_len: usize) -> bool {
    !value.is_empty() && value.len() <= max_len
}
