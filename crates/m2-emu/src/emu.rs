//! Placeholder for the emulated validators (scaffolded in T0, implemented in T13).

/// Scaffold marker so the workspace builds green.
pub fn scaffold() -> &'static str {
    "emu"
}

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold_smoke() {
        assert_eq!(super::scaffold(), "emu");
    }
}
