pub enum Status {
    Pending,
    WitnessGenerated,
    ProofGenererated,
    Failed,
}

impl Into<i32> for Status {
    fn into(self) -> i32 {
        match self {
            Status::Pending => 0,
            Status::WitnessGenerated => 1,
            Status::ProofGenererated => 2,
            Status::Failed => 3,
        }
    }
}

/// The signature pre-check's outcome, persisted to `proofs.precheck_verdict`
/// (a dedicated column, not `status`/`reason` -- see setup.sql's comment on
/// that column). Mirrors `crate::verifier::Verdict` one-for-one; kept as a
/// separate type rather than giving `Verdict` an `Into<i32>` impl directly,
/// so the DB's integer encoding doesn't leak into the verifier module that
/// has no other reason to know about persistence.
///
/// `Unavailable` is `Verdict::Skipped`'s persisted name: from the pipeline's
/// point of view every skip -- a sidecar process failure or the one residual
/// certificate-parseability gap alike -- means "this pre-check could not be
/// completed", which is what "unavailable" names.
pub enum PrecheckVerdict {
    Valid,
    Invalid,
    Unavailable,
}

impl From<&crate::verifier::Verdict> for PrecheckVerdict {
    fn from(v: &crate::verifier::Verdict) -> Self {
        match v {
            crate::verifier::Verdict::Valid => PrecheckVerdict::Valid,
            crate::verifier::Verdict::Invalid(_) => PrecheckVerdict::Invalid,
            crate::verifier::Verdict::Skipped(_) => PrecheckVerdict::Unavailable,
        }
    }
}

impl Into<i32> for PrecheckVerdict {
    fn into(self) -> i32 {
        match self {
            PrecheckVerdict::Valid => 0,
            PrecheckVerdict::Invalid => 1,
            PrecheckVerdict::Unavailable => 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precheck_verdict_codes_are_stable() {
        // These integers are persisted to the DB; changing them silently
        // would reinterpret every already-written row.
        assert_eq!(Into::<i32>::into(PrecheckVerdict::Valid), 0);
        assert_eq!(Into::<i32>::into(PrecheckVerdict::Invalid), 1);
        assert_eq!(Into::<i32>::into(PrecheckVerdict::Unavailable), 2);
    }

    #[test]
    fn verdict_maps_to_the_right_precheck_verdict() {
        use crate::verifier::Verdict;

        assert!(matches!(
            PrecheckVerdict::from(&Verdict::Valid),
            PrecheckVerdict::Valid
        ));
        assert!(matches!(
            PrecheckVerdict::from(&Verdict::Invalid("x".to_string())),
            PrecheckVerdict::Invalid
        ));
        assert!(matches!(
            PrecheckVerdict::from(&Verdict::Skipped("x".to_string())),
            PrecheckVerdict::Unavailable
        ));
    }
}
