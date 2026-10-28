//! Background tokio runtime that owns the LDAP session. The UI talks to it over channels,
//! so the interface never blocks on the network.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::mpsc as std_mpsc;

use ldap3::Scope;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::debug;

use crate::config::Profile;

use super::error::{ErrorKind, Failure};
use super::model::{ChildList, Entry, HitList};
use super::session::{ConnInfo, Creds, MsgSlot, Session};

pub type RequestId = u64;

#[derive(Debug, Clone)]
pub enum Request {
    Connect {
        profile: Box<Profile>,
        creds: Creds,
    },
    Disconnect,
    Children {
        dn: String,
        prefix: Option<String>,
        limit: usize,
    },
    Entry {
        dn: String,
    },
    /// `attrs`: extra attributes to return on each hit (result columns).
    Search {
        base: String,
        scope: Scope,
        filter: String,
        attrs: Vec<String>,
    },
    FindDn {
        dn: String,
        attrs: Vec<String>,
    },
    Members {
        dn: String,
        attrs: Vec<String>,
    },
    MemberOf {
        dn: String,
        nested: bool,
        attrs: Vec<String>,
    },
    Cancel {
        target: RequestId,
    },
}

impl Request {
    /// Replaces the extra attribute list on result-producing requests.
    pub fn with_attrs(self, new: Vec<String>) -> Request {
        match self {
            Request::Search { base, scope, filter, .. } => Request::Search { base, scope, filter, attrs: new },
            Request::FindDn { dn, .. } => Request::FindDn { dn, attrs: new },
            Request::Members { dn, .. } => Request::Members { dn, attrs: new },
            Request::MemberOf { dn, nested, .. } => Request::MemberOf { dn, nested, attrs: new },
            other => other,
        }
    }
}

#[derive(Debug)]
pub enum Response {
    Connected(ConnInfo),
    Children(ChildList),
    Entry(Box<Entry>),
    Hits(HitList),
    Failed(Failure),
}

#[derive(Debug)]
pub struct Reply {
    pub id: RequestId,
    pub response: Response,
}

pub struct Worker {
    tx: mpsc::UnboundedSender<(RequestId, Request)>,
    rx: std_mpsc::Receiver<Reply>,
    next_id: RequestId,
    _thread: std::thread::JoinHandle<()>,
}

impl Worker {
    pub fn spawn() -> Worker {
        let (tx, req_rx) = mpsc::unbounded_channel();
        let (reply_tx, rx) = std_mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("ldap-worker".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .expect("tokio runtime");
                rt.block_on(run(req_rx, reply_tx));
            })
            .expect("spawn worker thread");
        Worker { tx, rx, next_id: 1, _thread: thread }
    }

    pub fn send(&mut self, req: Request) -> RequestId {
        let id = self.next_id;
        self.next_id += 1;
        let _ = self.tx.send((id, req));
        id
    }

    pub fn try_recv(&self) -> Option<Reply> {
        self.rx.try_recv().ok()
    }
}

struct Running {
    handle: JoinHandle<()>,
    slot: MsgSlot,
}

async fn run(mut rx: mpsc::UnboundedReceiver<(RequestId, Request)>, reply: std_mpsc::Sender<Reply>) {
    let (conn_tx, mut conn_rx) = mpsc::unbounded_channel::<(RequestId, Result<Session, Failure>)>();
    let mut session: Option<Arc<Session>> = None;
    let mut running: HashMap<RequestId, Running> = HashMap::new();
    let mut connect_task: Option<JoinHandle<()>> = None;

    loop {
        tokio::select! {
            Some((id, res)) = conn_rx.recv() => {
                let response = match res {
                    Ok(s) => {
                        let info = s.info();
                        session = Some(Arc::new(s));
                        Response::Connected(info)
                    }
                    Err(f) => Response::Failed(f),
                };
                let _ = reply.send(Reply { id, response });
            }
            msg = rx.recv() => {
                let Some((id, req)) = msg else { break };
                running.retain(|_, r| !r.handle.is_finished());
                match req {
                    Request::Connect { profile, creds } => {
                        for (_, r) in running.drain() {
                            r.handle.abort();
                        }
                        if let Some(t) = connect_task.take() {
                            t.abort();
                        }
                        if let Some(old) = session.take() {
                            tokio::spawn(async move { old.unbind().await });
                        }
                        let tx = conn_tx.clone();
                        connect_task = Some(tokio::spawn(async move {
                            let res = Session::connect(*profile, creds).await;
                            let _ = tx.send((id, res));
                        }));
                    }
                    Request::Disconnect => {
                        for (_, r) in running.drain() {
                            r.handle.abort();
                        }
                        if let Some(old) = session.take() {
                            old.unbind().await;
                        }
                    }
                    Request::Cancel { target } => {
                        if let Some(r) = running.remove(&target) {
                            r.handle.abort();
                            if let Some(s) = &session {
                                let msgid = r.slot.load(Ordering::Relaxed);
                                let s = s.clone();
                                tokio::spawn(async move { s.abandon(msgid).await });
                            }
                            debug!(target, "cancelled");
                        }
                    }
                    op => {
                        let Some(s) = session.clone() else {
                            let _ = reply.send(Reply {
                                id,
                                response: Response::Failed(Failure::new(ErrorKind::Disconnected, "Not connected").hint("press R to reconnect")),
                            });
                            continue;
                        };
                        if s.is_closed() {
                            let _ = reply.send(Reply {
                                id,
                                response: Response::Failed(
                                    Failure::new(ErrorKind::Disconnected, "The connection to the server was lost").hint("press R to reconnect"),
                                ),
                            });
                            continue;
                        }
                        let slot: MsgSlot = Arc::new(AtomicI32::new(0));
                        let reply = reply.clone();
                        let task_slot = slot.clone();
                        let handle = tokio::spawn(async move {
                            let response = execute(&s, op, &task_slot).await;
                            let _ = reply.send(Reply { id, response });
                        });
                        running.insert(id, Running { handle, slot });
                    }
                }
            }
        }
    }
}

async fn execute(s: &Session, op: Request, slot: &MsgSlot) -> Response {
    let res = match op {
        Request::Children { dn, prefix, limit } => {
            s.list_children(&dn, prefix.as_deref(), limit, slot).await.map(Response::Children)
        }
        Request::Entry { dn } => s.read_entry(&dn, slot).await.map(|e| Response::Entry(Box::new(e))),
        Request::Search { base, scope, filter, attrs } => {
            s.search_with(&base, scope, &filter, &attrs, slot).await.map(Response::Hits)
        }
        Request::FindDn { dn, attrs } => s.find_dn_with(&dn, &attrs, slot).await.map(Response::Hits),
        Request::Members { dn, attrs } => s.members_with(&dn, &attrs, slot).await.map(Response::Hits),
        Request::MemberOf { dn, nested, attrs } => {
            s.member_of_with(&dn, nested, &attrs, slot).await.map(Response::Hits)
        }
        Request::Connect { .. } | Request::Disconnect | Request::Cancel { .. } => unreachable!("handled by the loop"),
    };
    res.unwrap_or_else(Response::Failed)
}
