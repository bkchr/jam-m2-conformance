//! Work packages, reports and guarantees: the artefacts the N3 lane puts on
//! the wire.
//!
//! The same shape as [`crate::tickets`] -- one method per artefact a lane
//! needs, computed once here and handed over whole. The authoring harness
//! does the work; what this module adds is a surface that does not leak it,
//! so a lane cannot reach past the oracle into the engine.

use jam_types::CoreIndex;

use crate::chain::{ChainError, RefChain};

/// One pass of the guaranteeing path: the package as a builder would submit
/// it, the report it refines to, the bundle those shards are coded from, and
/// a guarantee signed by the validators that hold the core.
///
/// Kept together because the lane needs all four and they are one
/// computation: CE 133 carries the package, CE 134 the bundle, CE 135 the
/// guarantee, and the report is what a block must come to carry.
pub struct GuaranteedWork {
    pub package: jam_types::WorkPackage,
    pub report: jam_std_common::WorkReport,
    pub bundle: Vec<u8>,
    pub guarantee: jam_std_common::ReportGuarantee,
}

impl RefChain {
    /// Build `items` into a package, refine it on `core`, and sign the
    /// guarantee.
    ///
    /// Nothing is submitted to the reference pool. `submit_work_items` would
    /// do both, and a harness that could not send a report without also
    /// adopting it would have no way to pose "guaranteed but never included".
    pub fn guarantee_work(
        &self,
        items: Vec<jam_node::hazmat::BuildItem>,
        core: CoreIndex,
    ) -> Result<GuaranteedWork, ChainError> {
        let mut harness = self.harness();
        let (package, xts) = harness.build_package(items);
        let wire = package.clone();
        let (report, bundle, _) = harness
            .try_compose_report(package, &xts, core)
            .map_err(|e| ChainError::Chain(format!("compose report: {e}")))?;
        let guarantee = harness
            .try_compose_guarantee(report.clone())
            .map_err(|e| ChainError::Chain(format!("compose guarantee: {e}")))?;
        Ok(GuaranteedWork {
            package: wire,
            report,
            bundle: bundle.to_vec(),
            guarantee,
        })
    }

    /// The validators assigned to `core` at `slot`.
    ///
    /// The assignment is a shuffle of validators across cores by the epoch's
    /// entropy, rotated every `rotation_period` slots. The harness reads it
    /// off the engine rather than recomputing it, so the rule it grades
    /// against is the one the engine applies.
    ///
    /// Read from the *storage* for `slot`, which is the source
    /// `try_compose_guarantee` signs against. Taking it from the chain's
    /// current epoch instead looks equivalent and is not: that reads one
    /// epoch's entropy whatever slot is asked about, so the two disagree as
    /// soon as the slot is outside the epoch the chain happens to be in, and
    /// a guarantee's signers then look like validators that do not hold the
    /// core.
    ///
    /// Not factored into a shared helper: polkajam's `CoreAssignments` lives
    /// behind a private module, so the value can be used but its type cannot
    /// be named, and a helper returning one has nothing to return it as.
    pub fn guarantors_for(&self, core: CoreIndex, slot: u32) -> Option<Vec<u16>> {
        self.harness()
            .storage(None)
            .core_assignments_for(slot)
            .ok()?
            .core_to_vals(core)
            .map(|vals| vals.to_vec())
    }

    /// The core validator `index` guarantees at `slot`.
    pub fn core_for(&self, index: u16, slot: u32) -> Option<CoreIndex> {
        self.harness()
            .storage(None)
            .core_assignments_for(slot)
            .ok()?
            .val_to_core(index)
    }
}

