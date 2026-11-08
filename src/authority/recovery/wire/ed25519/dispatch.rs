//! Bounded caller wait for the independently selected reference service.

use super::{AuthorityClock, Ed25519Security, SessionToken};
use crate::authority::identity::Entry;
use crate::authority::recovery::PersistentAuthority;
use crate::authority::recovery::ordered::witness::{Ed25519WitnessAuthority, WitnessHead};
use crate::authority::recovery::wire::{
    DeliveryWindow, WireCredentials, wait_for_ordered_wire_reply,
};
use crate::wire::codec::WireError;
use crate::wire::negotiation::Channel;
use std::num::NonZeroUsize;
use std::sync::mpsc::{SyncSender, sync_channel};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

type Authority<C> = PersistentAuthority<Ed25519Security<C>, WitnessHead<Ed25519WitnessAuthority>>;

enum Operation {
    Receive,
    ResolveDebit,
}

struct Work {
    operation: Operation,
    channel: Channel,
    token: SessionToken,
    packet: Vec<u8>,
    reply: SyncSender<Result<Vec<u8>, WireError>>,
}

/// Only the owned worker accesses the persistent authority or its signing configuration.
pub struct OrderedDispatcher {
    requests: SyncSender<Work>,
    worker: JoinHandle<()>,
    frame_limit: usize,
    max_wait: Duration,
}

impl OrderedDispatcher {
    pub fn start<C: AuthorityClock + Send + Sync + 'static>(
        mut authority: Authority<C>,
        capacity: NonZeroUsize,
        max_wait: Duration,
    ) -> std::io::Result<Self> {
        if max_wait.is_zero() || Instant::now().checked_add(max_wait).is_none() {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        let frame_limit = authority.security.config.max_frame;
        let (requests, queued) = sync_channel::<Work>(capacity.get());
        let worker = thread::Builder::new()
            .name("oip-ordered-dispatch".into())
            .spawn(move || {
                while let Ok(work) = queued.recv() {
                    let credentials = WireCredentials {
                        token: &work.token,
                        signature: &work.packet,
                        maintenance: None,
                        endorsement: None,
                        previous: None,
                        successor: None,
                    };
                    let result = match work.operation {
                        Operation::Receive => authority.receive_wire_response(
                            &work.channel,
                            Entry::Normal,
                            &work.packet,
                            &credentials,
                            DeliveryWindow::default(),
                        ),
                        Operation::ResolveDebit => authority.resolve_wire_debit_response(
                            &work.channel,
                            &work.packet,
                            &credentials,
                            false,
                        ),
                    };
                    // A dropped waiter never cancels completed authority work.
                    let _ = work.reply.try_send(result);
                }
            })?;
        Ok(Self {
            requests,
            worker,
            frame_limit,
            max_wait,
        })
    }

    pub fn receive(
        &self,
        channel: Channel,
        token: SessionToken,
        packet: Vec<u8>,
        deadline: Instant,
    ) -> Result<Vec<u8>, WireError> {
        self.submit(Operation::Receive, channel, token, packet, deadline)
    }

    pub fn resolve_debit(
        &self,
        channel: Channel,
        token: SessionToken,
        original: Vec<u8>,
        deadline: Instant,
    ) -> Result<Vec<u8>, WireError> {
        self.submit(Operation::ResolveDebit, channel, token, original, deadline)
    }

    fn submit(
        &self,
        operation: Operation,
        channel: Channel,
        token: SessionToken,
        packet: Vec<u8>,
        deadline: Instant,
    ) -> Result<Vec<u8>, WireError> {
        if packet.len() > self.frame_limit {
            return Err(WireError::InvalidFormat);
        }
        let now = Instant::now();
        let limit = now
            .checked_add(self.max_wait)
            .ok_or(WireError::RequestUnresolved)?;
        let deadline = deadline.min(limit);
        if now >= deadline {
            return Err(WireError::RequestUnresolved);
        }
        let (reply, received) = sync_channel(1);
        self.requests
            .try_send(Work {
                operation,
                channel,
                token,
                packet,
                reply,
            })
            .map_err(|_| WireError::RequestUnresolved)?;
        wait_for_ordered_wire_reply(&received, deadline)
    }

    pub fn shutdown(self) -> thread::Result<()> {
        drop(self.requests);
        self.worker.join()
    }
}

#[cfg(test)]
#[path = "dispatch_source_tests.rs"]
mod source_tests;
