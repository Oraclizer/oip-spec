//! Bounded ordered batches of signed acknowledgements and current reads.

use super::{
    CheckedInput, DeliveryWindow, OrderedInput, Received, WireCredentials, WireReply, WireSecurity,
    consume, hold, publication_guard, read_at, run_operand,
};
use crate::authority::identity::{Entry, Observation, ProductAuthority};
use crate::authority::reads::{CurrentRead, ReadError};
use crate::authority::recovery::ordered::OrderedPublication;
use crate::authority::recovery::schedule::{Class, Exchange, query_origin, slot};
use crate::authority::recovery::{
    AuthenticatedHead, PersistentAuthority, PublicationGuard, RecoveryError, RetainedImage,
};
use crate::wire::admission::{Arrival, TransportKey};
use crate::wire::codec::{WireError, check_declared_version, decode_packet};
use crate::wire::negotiation::Channel;
use crate::wire::operands::{Operands, ReadOperand, decode};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::ops::ControlFlow;

#[derive(Clone, Copy)]
pub struct WireScheduleLimits {
    pub max_occurrences: usize,
    pub max_adjacent_swaps: usize,
}

pub struct WireOccurrence<'a, S: WireSecurity> {
    /// A reply label, separate from authority and transport identity.
    pub label: u64,
    pub channel: &'a Channel,
    pub bytes: &'a [u8],
    pub credentials: &'a WireCredentials<'a, S>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireScheduleReply {
    Acknowledged(bool),
    Current(Result<CurrentRead, ReadError>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireScheduled {
    pub arrival: Arrival,
    pub reply: WireScheduleReply,
}

#[derive(Debug, Eq, PartialEq)]
pub struct WireOccurrenceReply {
    pub label: u64,
    pub reply: Result<WireScheduled, WireError>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct WireScheduleReport {
    pub exchanges: Vec<Exchange>,
    pub replies: Vec<WireOccurrenceReply>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireScheduleError {
    InvalidPlan,
    Wire(WireError),
}

#[derive(Clone, Copy)]
struct Candidate {
    class: Class,
    transport: TransportKey,
}

fn shape<S: WireSecurity>(
    occurrence: &WireOccurrence<'_, S>,
    security: &S,
) -> Result<Candidate, WireError> {
    if occurrence.channel.profile().version != 6 {
        return Err(WireError::UnsupportedVersion);
    }
    let frame_limit = security.frame_limit(occurrence.channel);
    check_declared_version(occurrence.bytes, frame_limit)?;
    let packet = decode_packet(occurrence.bytes, frame_limit)?;
    let core = packet.core();
    if !security.accepts_operation(occurrence.channel, core) {
        return Err(WireError::UnsupportedVersion);
    }
    let class = match decode(core, 1)? {
        Operands::Ack(ack) => slot(ack.key),
        Operands::Read(read @ ReadOperand::Current { .. }) => {
            let epoch = core.authority_epoch.ok_or(WireError::InvalidFormat)?;
            Class::observation(query_origin(read_at(read, epoch)))
        }
        _ => return Err(WireError::InvalidFormat),
    };
    Ok(Candidate {
        class,
        transport: TransportKey::for_core(core)?,
    })
}

fn batch_reply(reply: WireReply) -> Result<WireScheduleReply, WireError> {
    match reply {
        WireReply::Acknowledged(result) => Ok(WireScheduleReply::Acknowledged(result)),
        WireReply::Observation(Observation::Current(result)) => {
            Ok(WireScheduleReply::Current(result))
        }
        _ => Err(hold()),
    }
}

fn exchangeable(reply: Result<WireScheduled, WireError>) -> bool {
    matches!(
        reply,
        Ok(WireScheduled {
            reply: WireScheduleReply::Acknowledged(true) | WireScheduleReply::Current(Ok(_)),
            ..
        })
    )
}

struct Run {
    replies: Vec<Result<WireScheduled, WireError>>,
    checks: Vec<Option<CheckedInput>>,
}

fn run_order<S: WireSecurity>(
    product: &mut ProductAuthority<S>,
    occurrences: &[WireOccurrence<'_, S>],
    order: &[usize],
    candidates: &[Result<Candidate, WireError>],
    deployment: u64,
    input: OrderedInput<'_>,
) -> Result<Run, WireError> {
    let cut = product.reads.current_cut();
    let mut replies = vec![Err(hold()); occurrences.len()];
    let mut checks: Vec<_> = (0..occurrences.len()).map(|_| None).collect();
    for &index in order {
        let occurrence = &occurrences[index];
        if let Err(error) = candidates[index] {
            replies[index] = Err(error);
            continue;
        }
        match consume(
            product,
            occurrence.channel,
            Entry::Normal,
            occurrence.bytes,
            occurrence.credentials,
            DeliveryWindow::default(),
            deployment,
            Some(input),
            false,
        ) {
            Ok((Received { arrival, reply }, check, _)) => {
                replies[index] = Ok(WireScheduled {
                    arrival,
                    reply: batch_reply(reply)?,
                });
                checks[index] = Some(check);
            }
            Err(error) => replies[index] = Err(error),
        }
    }
    if product.reads.current_cut() != cut {
        return Err(hold());
    }
    Ok(Run { replies, checks })
}

struct Prepared {
    initial: RetainedImage,
    order: Vec<usize>,
    replies: Vec<Result<WireScheduled, WireError>>,
    checks: Vec<Option<CheckedInput>>,
    publication: OrderedPublication,
}

impl<S: WireSecurity, H: AuthenticatedHead> PersistentAuthority<S, H> {
    /// Compare compatible proposed exchanges on one ordered authority cut.
    /// Shape and authorization refusals stay with their original labels.
    /// Successful results are exposed after the prepared image is confirmed.
    pub fn schedule_wire(
        &mut self,
        occurrences: &[WireOccurrence<'_, S>],
        adjacent: &[usize],
    ) -> Result<WireScheduleReport, WireScheduleError> {
        let security = self.security.clone();
        let profile = self.profile;
        let connected = self.source_connected;
        if self.anchor.ordered_wire_control().is_none()
            || security.ordered_revocation_profile() != Some(profile)
        {
            return Err(WireScheduleError::Wire(WireError::InvalidSource));
        }
        let limits = security
            .ordered_schedule_limits()
            .ok_or(WireScheduleError::InvalidPlan)?;
        let mut labels = BTreeSet::new();
        if occurrences.is_empty()
            || occurrences.len() > limits.max_occurrences
            || adjacent.len() > limits.max_adjacent_swaps
            || occurrences.iter().any(|item| !labels.insert(item.label))
            || adjacent.iter().any(|&index| index >= occurrences.len() - 1)
        {
            return Err(WireScheduleError::InvalidPlan);
        }
        let candidates: Vec<_> = occurrences
            .iter()
            .map(|item| shape(item, security.as_ref()))
            .collect();
        let prepared = Cell::new(None);
        let refusal = Cell::new(None);
        self.transact_guarded(
            |anchor, head, product| {
                let attempt = (|| {
                    let authority = anchor.ordered_wire_control().ok_or_else(hold)?;
                    let observed = authority.observe().map_err(|_| hold())?;
                    if observed.head() != Some(head) {
                        return Err(hold());
                    }
                    let input = OrderedInput {
                        authority,
                        head,
                        observed: Some(&observed),
                    };
                    let initial = RetainedImage::capture(product);
                    let mut order: Vec<_> = (0..occurrences.len()).collect();
                    let mut selected = run_order(
                        product,
                        occurrences,
                        &order,
                        &candidates,
                        profile.deployment,
                        input,
                    )?;
                    let baseline_image = RetainedImage::capture(product);
                    let mut exchanges = vec![Exchange::Serialized; adjacent.len()];
                    for (attempt, &index) in adjacent.iter().enumerate() {
                        let (left, right) = (order[index], order[index + 1]);
                        let (Ok(a), Ok(b)) = (candidates[left], candidates[right]) else {
                            continue;
                        };
                        if !exchangeable(selected.replies[left])
                            || !exchangeable(selected.replies[right])
                            || a.transport == b.transport
                            || !a.class.compatible(b.class)
                        {
                            continue;
                        }
                        order.swap(index, index + 1);
                        let mut alternate =
                            initial.clone().open(profile, security.clone(), connected);
                        let exchanged = run_order(
                            &mut alternate,
                            occurrences,
                            &order,
                            &candidates,
                            profile.deployment,
                            input,
                        )?;
                        if selected.replies != exchanged.replies
                            || baseline_image != RetainedImage::capture(&alternate)
                        {
                            return Err(hold());
                        }
                        *product = alternate;
                        selected = exchanged;
                        exchanges[attempt] = Exchange::Exchanged;
                    }
                    let replies = occurrences
                        .iter()
                        .zip(&selected.replies)
                        .map(|(item, reply)| WireOccurrenceReply {
                            label: item.label,
                            reply: *reply,
                        })
                        .collect();
                    prepared.set(Some(Prepared {
                        initial,
                        order,
                        replies: selected.replies,
                        checks: selected.checks,
                        publication: OrderedPublication {
                            cut: observed,
                            debit: None,
                        },
                    }));
                    Ok(WireScheduleReport { exchanges, replies })
                })();
                match attempt {
                    Ok(report) => ControlFlow::Continue(Ok(report)),
                    Err(error) => ControlFlow::Break(Err(error)),
                }
            },
            true,
            || {
                let attempt = (|| {
                    let Prepared {
                        initial,
                        order,
                        replies,
                        mut checks,
                        publication,
                    } = prepared.take().ok_or_else(hold)?;
                    let mut replay = initial.open(profile, security.clone(), connected);
                    for index in order {
                        let Some(check) = checks[index].take() else {
                            continue;
                        };
                        let occurrence = &occurrences[index];
                        let core = check.core.clone();
                        let guard = publication_guard(
                            security.as_ref(),
                            occurrence.channel,
                            occurrence.bytes,
                            occurrence.credentials,
                            DeliveryWindow::default(),
                            profile.deployment,
                            check,
                        )?;
                        if !matches!(guard, PublicationGuard::Ordered(_)) {
                            return Err(hold());
                        }
                        let operands = decode(&core, 1)?;
                        let reply = run_operand(
                            &mut replay,
                            &core,
                            &operands,
                            Entry::Normal,
                            occurrence.credentials,
                            1,
                            true,
                        )?;
                        if replies[index].map(|result| result.reply) != Ok(batch_reply(reply)?) {
                            return Err(hold());
                        }
                    }
                    Ok(Some(PublicationGuard::Ordered(publication)))
                })();
                attempt.map_err(|error| {
                    refusal.set(Some(error));
                    RecoveryError::Hold
                })
            },
        )
        .map_err(|error| {
            WireScheduleError::Wire(refusal.get().unwrap_or(WireError::Recovery(error)))
        })?
        .map_err(WireScheduleError::Wire)
    }
}
