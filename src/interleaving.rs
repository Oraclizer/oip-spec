//! Executable interleaving witness for asset writes and authority rotation.

use crate::AssetId;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Write {
        asset: AssetId,
        expected_epoch: u64,
        value: u64,
    },
    RotateAuthority {
        asset: AssetId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    authority_epoch: u64,
    values: BTreeMap<AssetId, u64>,
}

impl State {
    pub fn new(authority_epoch: u64) -> Self {
        Self {
            authority_epoch,
            values: BTreeMap::new(),
        }
    }

    pub fn value(&self, asset: AssetId) -> u64 {
        self.values.get(&asset).copied().unwrap_or_default()
    }

    pub fn apply(&mut self, action: Action) -> bool {
        match action {
            Action::Write {
                asset,
                expected_epoch,
                value,
            } => {
                if expected_epoch != self.authority_epoch {
                    return false;
                }
                self.values.insert(asset, value);
            }
            Action::RotateAuthority { .. } => {
                let Some(epoch) = self.authority_epoch.checked_add(1) else {
                    return false;
                };
                self.authority_epoch = epoch;
            }
        }
        true
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Observation {
    pub left_accepted: bool,
    pub right_accepted: bool,
    pub state: State,
}

pub fn compare_orders(initial: &State, left: Action, right: Action) -> [Observation; 2] {
    let mut left_first = initial.clone();
    let left_reply = left_first.apply(left);
    let right_reply = left_first.apply(right);
    let mut right_first = initial.clone();
    let reverse_right_reply = right_first.apply(right);
    let reverse_left_reply = right_first.apply(left);
    [
        Observation {
            left_accepted: left_reply,
            right_accepted: right_reply,
            state: left_first,
        },
        Observation {
            left_accepted: reverse_left_reply,
            right_accepted: reverse_right_reply,
            state: right_first,
        },
    ]
}
