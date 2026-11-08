#[cfg(creusot)]
use creusot_std::prelude::ensures;

pub(crate) enum Reply<T> {
    Waiting,
    Rejected,
    Collected(T),
}

#[cfg_attr(creusot, ensures(result == (
    match stored {
        None => (Reply::Waiting, false),
        Some((matches, ready, outcome)) =>
            if !matches { (Reply::Rejected, false) }
            else if ready { (Reply::Collected(outcome), true) }
            else { (Reply::Waiting, false) },
    }
)))]
pub(crate) fn retained_completion<T: Copy>(stored: Option<(bool, bool, T)>) -> (Reply<T>, bool) {
    let Some((matches, ready, outcome)) = stored else {
        return (Reply::Waiting, false);
    };
    if !matches {
        (Reply::Rejected, false)
    } else if ready {
        (Reply::Collected(outcome), true)
    } else {
        (Reply::Waiting, false)
    }
}
