//! Placeholder for the P0 chain-authoring oracle (scaffolded in T0, implemented in T10).

/// Scaffold marker so the workspace builds green.
pub fn scaffold() -> &'static str {
    "chain"
}

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold_smoke() {
        assert_eq!(super::scaffold(), "chain");
    }
}
