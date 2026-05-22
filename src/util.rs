//! Small shared helpers with no domain dependencies.

/// Truncate `input` to at most `max_len` bytes (UTF-8 safe at char boundary not guaranteed; same as prior behavior).
pub fn truncate_str(input: &str, max_len: usize) -> String {
    if input.len() <= max_len {
        return input.to_string();
    }
    format!("{}…", &input[..max_len])
}

#[cfg(test)]
mod tests {
    use super::truncate_str;

    #[test]
    fn truncate_short_unchanged() {
        assert_eq!(truncate_str("hi", 10), "hi");
    }

    #[test]
    fn truncate_long_adds_ellipsis() {
        let out = truncate_str("abcdefghij", 5);
        assert!(out.starts_with("abcde"));
        assert!(out.ends_with('…'));
        assert!(out.len() > 5);
    }
}
