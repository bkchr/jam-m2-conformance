//! Placeholder for the scenario DSL (scaffolded in T0, implemented in T12).

/// Scaffold marker so the workspace builds green.
pub fn scaffold() -> &'static str {
    "dsl"
}

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold_smoke() {
        assert_eq!(super::scaffold(), "dsl");
    }
}
