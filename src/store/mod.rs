//! Records and how they merge (P59). The core is generic: a record is a kind,
//! an identifier and flat fields; it knows nothing about sessions or sets.
//!
//! Every write carries a [`Stamp`]. Per field, the write with the highest
//! stamp wins (last-writer-wins); a deletion hides the record and every
//! field written before it. Merging is commutative and idempotent, so the
//! result doesn't depend on the order in which batches arrive (later: from
//! other devices).

pub(crate) mod hlc;
pub(crate) mod journal;

use std::collections::BTreeMap;

use serde::de::{self, SeqAccess, Visitor};
use serde::ser::SerializeTuple;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};
use zeroize::Zeroize;

use crate::{Error, Result};

/// Overwrites a text value before its memory is freed: record texts and the
/// core's file keys (security review L2). Numbers can't be wiped this way.
fn wipe(value: &mut Value) {
    if let Value::String(s) = value {
        s.zeroize();
    }
}

/// Field values are the user's data or keys, so `Debug` shows names only.
fn field_names<'a>(names: impl Iterator<Item = &'a String>) -> Vec<&'a str> {
    names.map(String::as_str).collect()
}

/// A record as the app sees it.
#[derive(Clone, PartialEq)]
pub struct Record {
    pub kind: String,
    pub id: String,
    pub fields: Map<String, Value>,
}

impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Record")
            .field("kind", &self.kind)
            .field("id", &self.id)
            .field("fields", &field_names(self.fields.keys()))
            .finish()
    }
}

/// A change the app commits. A put sets the given fields and keeps all
/// others; a field set to `null` is cleared.
#[derive(Clone, PartialEq)]
pub enum Change {
    Put {
        kind: String,
        id: String,
        fields: Map<String, Value>,
    },
    Delete {
        kind: String,
        id: String,
    },
}

impl std::fmt::Debug for Change {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Change::Put { kind, id, fields } => f
                .debug_struct("Put")
                .field("kind", kind)
                .field("id", id)
                .field("fields", &field_names(fields.keys()))
                .finish(),
            Change::Delete { kind, id } => f
                .debug_struct("Delete")
                .field("kind", kind)
                .field("id", id)
                .finish(),
        }
    }
}

pub(crate) const MAX_STRING_BYTES: usize = 64 * 1024;
pub(crate) const MAX_CHANGES: usize = 10_000;

fn valid_name(s: &str, max: usize) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= max
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

fn valid_id(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

/// Kinds starting with "_" are the core's own and can't be read or written
/// by the app.
pub(crate) fn check_kind(kind: &str) -> Result<()> {
    if valid_name(kind, 32) {
        Ok(())
    } else {
        Err(Error::InvalidInput("record kind"))
    }
}

pub(crate) fn validate(changes: &[Change]) -> Result<()> {
    if changes.is_empty() || changes.len() > MAX_CHANGES {
        return Err(Error::InvalidInput("number of changes"));
    }
    for change in changes {
        let (kind, id) = match change {
            Change::Put { kind, id, .. } | Change::Delete { kind, id } => (kind, id),
        };
        check_kind(kind)?;
        if !valid_id(id) {
            return Err(Error::InvalidInput("record id"));
        }
        if let Change::Put { fields, .. } = change {
            for (name, value) in fields {
                if !valid_name(name, 32) {
                    return Err(Error::InvalidInput("field name"));
                }
                match value {
                    Value::Null | Value::Bool(_) | Value::Number(_) => {}
                    Value::String(s) if s.len() <= MAX_STRING_BYTES => {}
                    Value::String(_) => return Err(Error::InvalidInput("text too long")),
                    Value::Array(_) | Value::Object(_) => {
                        return Err(Error::InvalidInput("fields must be flat"));
                    }
                }
            }
        }
    }
    Ok(())
}

/// The version of one write: the batch's clock value, the writing device, the
/// batch's sequence number and the operation's position in the batch. The
/// order is total, so there are no ties.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Stamp {
    pub hlc: u64,
    pub device: [u8; 16],
    pub seq: u64,
    pub index: u32,
}

impl Serialize for Stamp {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let mut t = s.serialize_tuple(4)?;
        t.serialize_element(&self.hlc)?;
        t.serialize_element(&hex16(&self.device))?;
        t.serialize_element(&self.seq)?;
        t.serialize_element(&self.index)?;
        t.end()
    }
}

impl<'de> Deserialize<'de> for Stamp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Stamp;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("[hlc, device, seq, index]")
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Stamp, A::Error> {
                let missing = || de::Error::custom("stamp too short");
                let hlc = a.next_element()?.ok_or_else(missing)?;
                let device: String = a.next_element()?.ok_or_else(missing)?;
                let seq = a.next_element()?.ok_or_else(missing)?;
                let index = a.next_element()?.ok_or_else(missing)?;
                if a.next_element::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom("stamp too long"));
                }
                let device = unhex16(&device).ok_or_else(|| de::Error::custom("device id"))?;
                Ok(Stamp {
                    hlc,
                    device,
                    seq,
                    index,
                })
            }
        }
        d.deserialize_tuple(4, V)
    }
}

pub(crate) fn hex16(b: &[u8; 16]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub(crate) fn unhex16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// One operation inside a batch.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum Op {
    Put {
        kind: String,
        id: String,
        fields: Map<String, Value>,
    },
    Del {
        kind: String,
        id: String,
    },
    /// A record's surviving state with its original stamps; written only by
    /// compaction, so a later merge with other devices stays correct.
    Snap {
        kind: String,
        id: String,
        alive: Stamp,
        fields: Vec<(String, Stamp, Value)>,
    },
}

impl Drop for Op {
    fn drop(&mut self) {
        match self {
            Op::Put { fields, .. } => fields.values_mut().for_each(wipe),
            Op::Del { .. } => {}
            Op::Snap { fields, .. } => fields.iter_mut().for_each(|(_, _, v)| wipe(v)),
        }
    }
}

impl std::fmt::Debug for Op {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Op::Put { kind, id, fields } => f
                .debug_struct("Put")
                .field("kind", kind)
                .field("id", id)
                .field("fields", &field_names(fields.keys()))
                .finish(),
            Op::Del { kind, id } => f
                .debug_struct("Del")
                .field("kind", kind)
                .field("id", id)
                .finish(),
            Op::Snap {
                kind, id, fields, ..
            } => f
                .debug_struct("Snap")
                .field("kind", kind)
                .field("id", id)
                .field("fields", &field_names(fields.iter().map(|(n, _, _)| n)))
                .finish(),
        }
    }
}

/// What one journal frame holds.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Batch {
    pub hlc: u64,
    pub ops: Vec<Op>,
}

impl From<Change> for Op {
    fn from(c: Change) -> Self {
        match c {
            Change::Put { kind, id, fields } => Op::Put { kind, id, fields },
            Change::Delete { kind, id } => Op::Del { kind, id },
        }
    }
}

#[derive(Clone, Default, PartialEq)]
pub(crate) struct RecordState {
    /// The latest put or snapshot.
    alive: Option<Stamp>,
    /// The latest deletion.
    deleted: Option<Stamp>,
    fields: BTreeMap<String, (Stamp, Value)>,
}

impl Drop for RecordState {
    fn drop(&mut self) {
        self.fields.values_mut().for_each(|(_, v)| wipe(v));
    }
}

impl std::fmt::Debug for RecordState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordState")
            .field("alive", &self.alive)
            .field("deleted", &self.deleted)
            .field("fields", &field_names(self.fields.keys()))
            .finish()
    }
}

impl RecordState {
    fn visible(&self) -> bool {
        match (self.alive, self.deleted) {
            (Some(a), Some(d)) => a > d,
            (Some(_), None) => true,
            (None, _) => false,
        }
    }

    fn visible_fields(&self) -> impl Iterator<Item = (&String, &Stamp, &Value)> {
        let deleted = self.deleted;
        self.fields
            .iter()
            .filter(move |(_, (s, v))| deleted.is_none_or(|d| *s > d) && !v.is_null())
            .map(|(n, (s, v))| (n, s, v))
    }

    fn write_field(&mut self, name: &str, stamp: Stamp, value: &Value) {
        match self.fields.get(name) {
            Some((s, _)) if *s >= stamp => {}
            _ => {
                self.fields.insert(name.to_owned(), (stamp, value.clone()));
            }
        }
    }
}

/// All records in memory, rebuilt from the journal at unlock. Dropping it
/// (when the vault locks) wipes the texts.
#[derive(Clone, Default, PartialEq)]
pub(crate) struct Store {
    records: BTreeMap<(String, String), RecordState>,
    /// Field writes since the last compaction, for deciding when to compact.
    writes: u64,
    deletes: u64,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("records", &self.records.len())
            .field("writes", &self.writes)
            .field("deletes", &self.deletes)
            .finish()
    }
}

impl Store {
    /// Applies one batch read from (or just written to) the journal.
    pub(crate) fn apply(&mut self, batch: &Batch, device: [u8; 16], seq: u64) {
        for (i, op) in batch.ops.iter().enumerate() {
            let stamp = Stamp {
                hlc: batch.hlc,
                device,
                seq,
                index: i as u32,
            };
            self.apply_op(op, stamp);
        }
    }

    pub(crate) fn apply_op(&mut self, op: &Op, stamp: Stamp) {
        match op {
            Op::Put { kind, id, fields } => {
                let r = self.records.entry((kind.clone(), id.clone())).or_default();
                r.alive = r.alive.max(Some(stamp));
                for (name, value) in fields {
                    r.write_field(name, stamp, value);
                }
                self.writes += fields.len() as u64;
            }
            Op::Del { kind, id } => {
                let r = self.records.entry((kind.clone(), id.clone())).or_default();
                r.deleted = r.deleted.max(Some(stamp));
                self.deletes += 1;
            }
            Op::Snap {
                kind,
                id,
                alive,
                fields,
            } => {
                let r = self.records.entry((kind.clone(), id.clone())).or_default();
                r.alive = r.alive.max(Some(*alive));
                for (name, s, value) in fields {
                    r.write_field(name, *s, value);
                }
                self.writes += fields.len() as u64;
            }
        }
    }

    /// The visible records of one kind, sorted by id.
    pub(crate) fn records(&self, kind: &str) -> Vec<Record> {
        self.records
            .range((kind.to_owned(), String::new())..)
            .take_while(|((k, _), _)| k == kind)
            .filter(|(_, r)| r.visible())
            .map(|((k, id), r)| Record {
                kind: k.clone(),
                id: id.clone(),
                fields: r
                    .visible_fields()
                    .map(|(n, _, v)| (n.clone(), v.clone()))
                    .collect(),
            })
            .collect()
    }

    pub(crate) fn get(&self, kind: &str, id: &str) -> Option<Record> {
        let r = self.records.get(&(kind.to_owned(), id.to_owned()))?;
        r.visible().then(|| Record {
            kind: kind.to_owned(),
            id: id.to_owned(),
            fields: r
                .visible_fields()
                .map(|(n, _, v)| (n.clone(), v.clone()))
                .collect(),
        })
    }

    /// Whether a visible record exists, without copying it.
    pub(crate) fn exists(&self, kind: &str, id: &str) -> bool {
        self.records
            .get(&(kind.to_owned(), id.to_owned()))
            .is_some_and(RecordState::visible)
    }

    /// One visible text field, borrowed rather than copied (for the core's
    /// file keys, which shouldn't be duplicated in memory).
    pub(crate) fn field_str(&self, kind: &str, id: &str, field: &str) -> Option<&str> {
        let r = self.records.get(&(kind.to_owned(), id.to_owned()))?;
        if !r.visible() {
            return None;
        }
        r.visible_fields()
            .find(|(n, _, _)| n.as_str() == field)
            .and_then(|(_, _, v)| v.as_str())
    }

    /// The ids of the visible records of one kind, sorted.
    pub(crate) fn ids(&self, kind: &str) -> Vec<String> {
        self.records
            .range((kind.to_owned(), String::new())..)
            .take_while(|((k, _), _)| k == kind)
            .filter(|(_, r)| r.visible())
            .map(|((_, id), _)| id.clone())
            .collect()
    }

    /// The highest clock value of any write, so new writes come after it.
    pub(crate) fn max_hlc(&self) -> u64 {
        self.records
            .values()
            .flat_map(|r| {
                r.alive
                    .iter()
                    .chain(r.deleted.iter())
                    .map(|s| s.hlc)
                    .chain(r.fields.values().map(|(s, _)| s.hlc))
            })
            .max()
            .unwrap_or(0)
    }

    /// The surviving state as snapshot operations, for compaction: deleted
    /// records and overwritten or deleted values are left out.
    pub(crate) fn snapshot(&self) -> Vec<Op> {
        self.records
            .iter()
            .filter(|(_, r)| r.visible())
            .map(|((kind, id), r)| Op::Snap {
                kind: kind.clone(),
                id: id.clone(),
                alive: r.alive.expect("visible records are alive"),
                fields: r
                    .visible_fields()
                    .map(|(n, s, v)| (n.clone(), *s, v.clone()))
                    .collect(),
            })
            .collect()
    }

    /// The store as rebuilt from a snapshot: same records, no history.
    pub(crate) fn compacted(&self) -> Store {
        let mut s = Store::default();
        for op in self.snapshot() {
            if let Op::Snap { alive, .. } = &op {
                let alive = *alive;
                s.apply_op(&op, alive);
            }
        }
        s
    }

    /// Whether the journal holds much that is no longer visible: any
    /// deletion, or more overwritten than live values.
    pub(crate) fn needs_compaction(&self) -> bool {
        let live: u64 = self
            .records
            .values()
            .map(|r| r.visible_fields().count() as u64)
            .sum();
        self.deletes > 0 || self.writes > 2 * live.max(32)
    }
}

#[cfg(test)]
mod tests;
