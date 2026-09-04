//! Placeholder for the `framing` module (scaffolded in T0, implemented by its wave task).

/// Scaffold marker so the workspace builds green before the module is implemented.
pub fn scaffold() -> &'static str {
    "framing"
}

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold_smoke() {
        assert_eq!(super::scaffold(), "framing");
    }
}
