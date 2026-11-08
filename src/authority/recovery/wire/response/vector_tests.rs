use super::*;

#[test]
fn duplicate_outcomes_carry_their_codes_and_the_original_commit() {
    let commit = CommitRef { position: 7 };
    for (reply, code, number) in [
        (OutcomeReply::DuplicateDecision, ResponseCode::DuplicateDecision, 23),
        (
            OutcomeReply::DuplicateSettlement(TerminalKind::Confirmed),
            ResponseCode::DuplicateConfirmed,
            24,
        ),
        (
            OutcomeReply::DuplicateSettlement(TerminalKind::Reversed),
            ResponseCode::DuplicateReversed,
            25,
        ),
    ] {
        let result = ResponseResult::ordinary(Outcome::committed(reply, commit));
        assert_eq!(result.code, code);
        assert_eq!(result.code as u64, number);
        assert_eq!(result.commit, Some(commit));
        // A duplicate is a recorded result and must name the original commit.
        assert_eq!(ResponseStatus::decode(1, number, true), Ok(ResponseStatus::Known(code)));
        assert_eq!(ResponseStatus::decode(1, number, false), Err(BAD));
    }
}

#[test]
fn a_confiscation_without_a_destination_is_a_refusal_without_a_commit() {
    let result = ResponseResult::legal(LegalReply::Refused(Refusal::MissingDestination));
    assert_eq!(result.code, ResponseCode::LegalMissingDestination);
    assert_eq!(result.code as u64, 37);
    assert_eq!(result.commit, None);
    assert_eq!(
        ResponseStatus::decode(1, 37, false),
        Ok(ResponseStatus::Known(ResponseCode::LegalMissingDestination))
    );
    assert_eq!(ResponseStatus::decode(1, 37, true), Err(BAD));
}

#[path = "boundary_value_tests.rs"]
pub(super) mod boundary_values;
