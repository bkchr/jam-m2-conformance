//! Typed codecs for every UP/CE message (GP codec via `jam-types`/`codec`).
//! One module per protocol family: `up0`, `ce128_129`, `ce131_136`,
//! `ce137_148`, `ce141_145`.

pub mod ce128_129;
pub mod ce131_136;
pub mod ce137_148;
pub mod ce141_145;
pub mod up0;

/// Scaffold marker so the workspace builds green before the modules land.
pub fn scaffold() -> &'static str {
    "codec"
}

#[cfg(test)]
mod tests {
    #[test]
    fn scaffold_smoke() {
        assert_eq!(super::scaffold(), "codec");
    }
}
