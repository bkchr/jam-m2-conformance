//! Placeholder for the CLI orchestration (scaffolded in T0, implemented in T20).

/// Scaffold marker so the workspace builds green.
pub fn scaffold() -> &'static str {
    "cli"
}

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold_smoke() {
        assert_eq!(super::scaffold(), "cli");
    }
}
