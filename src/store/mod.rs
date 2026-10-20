//! Records and how they merge (P59). The core is generic: a record is a kind,
//! an identifier and flat fields; it knows nothing about sessions or sets.
//!
//! Every write carries a [`Stamp`]. Per field, the write with the highest
//! stamp wins (last-writer-wins); a deletion hides the record and every
//! field written before it. Merging is commutative and idempotent, so the
//! result doesn't depend on the order in which batches arrive (later: from
//! other devices).

pub(crate) mod codec;
pub(crate) mod hlc;
pub(crate) mod journal;

use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};

use serde::de::{self, SeqAccess, Visitor};
use serde::ser::SerializeTuple;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Number, Value};
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

// ---- The store in memory (D55 (2)) -------------------------------------------
//
// Compact, because unlock keeps every record in memory: kinds and field names
// are kept once and referred to by number, ids and values in UUID form take
// 16 bytes, and each record's fields sit in one sorted vector that points into
// the record's few distinct stamps.

/// A kind or a field name, as its number in the store's table of names.
type Name = u32;

/// The kinds and field names in a store, each kept once.
#[derive(Clone, Default)]
struct Names {
    names: Vec<Box<str>>,
    numbers: HashMap<Box<str>, Name>,
}

impl Names {
    fn intern(&mut self, s: &str) -> Name {
        if let Some(&n) = self.numbers.get(s) {
            return n;
        }
        let n = self.names.len() as Name;
        self.names.push(s.into());
        self.numbers.insert(s.into(), n);
        n
    }

    fn find(&self, s: &str) -> Option<Name> {
        self.numbers.get(s).copied()
    }

    fn get(&self, n: Name) -> &str {
        &self.names[n as usize]
    }
}

/// A record id: a UUID in canonical form takes 16 bytes, any other id is kept
/// as text. Ids sort as their texts do.
#[derive(Clone, PartialEq, Eq)]
enum Id {
    Uuid([u8; 16]),
    Text(Box<str>),
}

impl Id {
    fn new(s: &str) -> Id {
        codec::uuid_bytes(s).map_or_else(|| Id::Text(s.into()), Id::Uuid)
    }

    /// The smallest id, where the records of a kind begin.
    fn first() -> Id {
        Id::Text(Box::default())
    }

    fn with_text<R>(&self, f: impl FnOnce(&str) -> R) -> R {
        match self {
            Id::Uuid(b) => f(std::str::from_utf8(&codec::uuid_ascii(b)).expect("ASCII")),
            Id::Text(s) => f(s),
        }
    }

    fn to_text(&self) -> String {
        self.with_text(str::to_owned)
    }
}

impl Ord for Id {
    fn cmp(&self, other: &Id) -> Ordering {
        match (self, other) {
            // Hex digits sort like the bytes they stand for.
            (Id::Uuid(a), Id::Uuid(b)) => a.cmp(b),
            (Id::Text(a), Id::Text(b)) => a.cmp(b),
            _ => self.with_text(|a| other.with_text(|b| a.cmp(b))),
        }
    }
}

impl PartialOrd for Id {
    fn partial_cmp(&self, other: &Id) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A field value. Smaller than a JSON value, and every kind can be wiped.
#[derive(Clone, PartialEq)]
enum Val {
    Null,
    Bool(bool),
    Uint(u64),
    /// Negative only: non-negative integers are `Uint`, as in JSON.
    Int(i64),
    Float(f64),
    Text(Box<str>),
    /// A text in canonical UUID form, usually another record's id.
    Uuid([u8; 16]),
}

impl Val {
    fn new(v: &Value) -> Val {
        match v {
            Value::Null => Val::Null,
            Value::Bool(b) => Val::Bool(*b),
            Value::Number(n) => match (n.as_u64(), n.as_i64()) {
                (Some(u), _) => Val::Uint(u),
                (None, Some(i)) => Val::Int(i),
                (None, None) => n.as_f64().map_or(Val::Null, Val::Float),
            },
            Value::String(s) => {
                codec::uuid_bytes(s).map_or_else(|| Val::Text(s.as_str().into()), Val::Uuid)
            }
            // Validation, and both journal formats, keep fields flat.
            Value::Array(_) | Value::Object(_) => Val::Null,
        }
    }

    fn to_value(&self) -> Value {
        match self {
            Val::Null => Value::Null,
            Val::Bool(b) => Value::Bool(*b),
            Val::Uint(u) => Value::from(*u),
            Val::Int(i) => Value::from(*i),
            Val::Float(f) => Number::from_f64(*f).map_or(Value::Null, Value::Number),
            Val::Text(s) => Value::String(s.to_string()),
            Val::Uuid(b) => Value::String(codec::uuid_text(b)),
        }
    }

    fn wipe(&mut self) {
        match self {
            Val::Null => {}
            Val::Bool(b) => b.zeroize(),
            Val::Uint(u) => u.zeroize(),
            Val::Int(i) => i.zeroize(),
            Val::Float(f) => f.zeroize(),
            Val::Text(s) => s.zeroize(),
            Val::Uuid(b) => b.zeroize(),
        }
    }
}

#[derive(Clone)]
struct Field {
    name: Name,
    /// The field's place in its record's stamps.
    stamp: u32,
    value: Val,
}

#[derive(Clone, Default)]
struct Rec {
    /// The latest put or snapshot.
    alive: Option<Stamp>,
    /// The latest deletion; boxed, as few records have one.
    deleted: Option<Box<Stamp>>,
    /// The stamps the fields were written with, each once.
    stamps: Vec<Stamp>,
    /// Sorted by name.
    fields: Vec<Field>,
}

impl Drop for Rec {
    fn drop(&mut self) {
        self.fields.iter_mut().for_each(|f| f.value.wipe());
    }
}

impl Rec {
    fn visible(&self) -> bool {
        match (self.alive, self.deleted.as_deref()) {
            (Some(a), Some(d)) => a > *d,
            (Some(_), None) => true,
            (None, _) => false,
        }
    }

    fn visible_fields(&self) -> impl Iterator<Item = (&Field, &Stamp)> {
        let deleted = self.deleted.as_deref().copied();
        self.fields
            .iter()
            .map(|f| (f, &self.stamps[f.stamp as usize]))
            .filter(move |(f, s)| deleted.is_none_or(|d| **s > d) && f.value != Val::Null)
    }

    fn field(&self, name: Name) -> Option<&Field> {
        let i = self.fields.binary_search_by_key(&name, |f| f.name).ok()?;
        Some(&self.fields[i])
    }

    /// Writes one operation's fields, each where it is newer than what the
    /// record holds, then forgets the stamps no field uses any more.
    fn write(&mut self, writes: &[(Name, Stamp, &Value)]) {
        let held = self.fields.len();
        let find =
            |fields: &[Field], name: Name| fields[..held].binary_search_by_key(&name, |f| f.name);
        let new = writes
            .iter()
            .filter(|(n, ..)| find(&self.fields, *n).is_err())
            .count();
        self.reserve(new);
        let mut replaced = false;
        for &(name, stamp, value) in writes {
            match find(&self.fields, name) {
                Ok(i) => {
                    if self.stamps[self.fields[i].stamp as usize] >= stamp {
                        continue;
                    }
                    let s = self.stamp_number(stamp);
                    let f = &mut self.fields[i];
                    f.value.wipe();
                    f.value = Val::new(value);
                    f.stamp = s;
                    replaced = true;
                }
                Err(_) => {
                    let s = self.stamp_number(stamp);
                    self.fields.push(Field {
                        name,
                        stamp: s,
                        value: Val::new(value),
                    });
                }
            }
        }
        if self.fields.len() > held {
            // In place: a stable sort would copy fields into a buffer it frees
            // unwiped.
            self.fields.sort_unstable_by_key(|f| f.name);
            // The same new name twice (only a damaged batch could hold that):
            // the later stamp wins, as for any other write.
            let stamps = &self.stamps;
            let before = self.fields.len();
            self.fields.dedup_by(|later, kept| {
                if later.name != kept.name {
                    return false;
                }
                if stamps[later.stamp as usize] > stamps[kept.stamp as usize] {
                    std::mem::swap(later, kept);
                }
                later.value.wipe();
                true
            });
            replaced |= self.fields.len() < before;
        }
        if replaced {
            self.forget_unused_stamps();
        }
    }

    /// Room for `more` fields. Growing copies the fields into a new buffer and
    /// wipes the old one, which `Vec` would free as it is.
    fn reserve(&mut self, more: usize) {
        let needed = self.fields.len() + more;
        if needed <= self.fields.capacity() {
            return;
        }
        let capacity = if self.fields.is_empty() {
            needed
        } else {
            needed.max(self.fields.len() + self.fields.len() / 2)
        };
        let mut grown = Vec::with_capacity(capacity);
        grown.extend(self.fields.iter().cloned());
        let mut old = std::mem::replace(&mut self.fields, grown);
        old.iter_mut().for_each(|f| f.value.wipe());
    }

    /// A stamp's place in `stamps`, added if new. Records hold few distinct
    /// stamps, and the last one is checked first.
    fn stamp_number(&mut self, stamp: Stamp) -> u32 {
        if self.stamps.last() != Some(&stamp) {
            match self.stamps.iter().position(|s| *s == stamp) {
                Some(i) => return i as u32,
                None => {
                    // Exactly: most records keep a single stamp, and `push`
                    // would make room for four.
                    self.stamps.reserve_exact(1);
                    self.stamps.push(stamp);
                }
            }
        }
        (self.stamps.len() - 1) as u32
    }

    fn forget_unused_stamps(&mut self) {
        let mut number = vec![u32::MAX; self.stamps.len()];
        for f in &self.fields {
            number[f.stamp as usize] = 0;
        }
        let mut kept = 0;
        for (i, n) in number.iter_mut().enumerate() {
            if *n == 0 {
                self.stamps[kept] = self.stamps[i];
                *n = kept as u32;
                kept += 1;
            }
        }
        self.stamps.truncate(kept);
        for f in &mut self.fields {
            f.stamp = number[f.stamp as usize];
        }
    }
}

/// All records in memory, rebuilt from the journal at unlock. Dropping it
/// (when the vault locks) wipes the values.
#[derive(Clone, Default)]
pub(crate) struct Store {
    names: Names,
    records: BTreeMap<(Name, Id), Rec>,
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

    fn record_mut(&mut self, kind: &str, id: &str) -> &mut Rec {
        let kind = self.names.intern(kind);
        self.records.entry((kind, Id::new(id))).or_default()
    }

    pub(crate) fn apply_op(&mut self, op: &Op, stamp: Stamp) {
        match op {
            Op::Put { kind, id, fields } => {
                let writes: Vec<_> = fields
                    .iter()
                    .map(|(n, v)| (self.names.intern(n), stamp, v))
                    .collect();
                let r = self.record_mut(kind, id);
                r.alive = r.alive.max(Some(stamp));
                r.write(&writes);
                self.writes += fields.len() as u64;
            }
            Op::Del { kind, id } => {
                let r = self.record_mut(kind, id);
                if r.deleted.as_deref().is_none_or(|d| *d < stamp) {
                    r.deleted = Some(Box::new(stamp));
                }
                self.deletes += 1;
            }
            Op::Snap {
                kind,
                id,
                alive,
                fields,
            } => {
                let writes: Vec<_> = fields
                    .iter()
                    .map(|(n, s, v)| (self.names.intern(n), *s, v))
                    .collect();
                let r = self.record_mut(kind, id);
                r.alive = r.alive.max(Some(*alive));
                r.write(&writes);
                self.writes += fields.len() as u64;
            }
        }
    }

    fn rec(&self, kind: &str, id: &str) -> Option<&Rec> {
        let kind = self.names.find(kind)?;
        self.records.get(&(kind, Id::new(id)))
    }

    /// The records of one kind, in id order.
    fn kind(&self, kind: &str) -> impl Iterator<Item = (&Id, &Rec)> {
        let k = self.names.find(kind);
        k.into_iter().flat_map(move |k| {
            self.records
                .range((k, Id::first())..)
                .take_while(move |((n, _), _)| *n == k)
                .map(|((_, id), r)| (id, r))
        })
    }

    fn record(&self, kind: &str, id: String, r: &Rec) -> Record {
        Record {
            kind: kind.to_owned(),
            id,
            fields: r
                .visible_fields()
                .map(|(f, _)| (self.names.get(f.name).to_owned(), f.value.to_value()))
                .collect(),
        }
    }

    /// The visible records of one kind, sorted by id.
    pub(crate) fn records(&self, kind: &str) -> Vec<Record> {
        self.kind(kind)
            .filter(|(_, r)| r.visible())
            .map(|(id, r)| self.record(kind, id.to_text(), r))
            .collect()
    }

    pub(crate) fn get(&self, kind: &str, id: &str) -> Option<Record> {
        let r = self.rec(kind, id)?;
        r.visible().then(|| self.record(kind, id.to_owned(), r))
    }

    /// Whether a visible record exists, without copying it.
    pub(crate) fn exists(&self, kind: &str, id: &str) -> bool {
        self.rec(kind, id).is_some_and(Rec::visible)
    }

    /// One visible text field, borrowed rather than copied when it is kept
    /// as text (for the core's file keys, which shouldn't be duplicated in
    /// memory).
    pub(crate) fn field_str(&self, kind: &str, id: &str, field: &str) -> Option<Cow<'_, str>> {
        let r = self.rec(kind, id).filter(|r| r.visible())?;
        let f = r.field(self.names.find(field)?)?;
        let stamp = r.stamps[f.stamp as usize];
        if r.deleted.as_deref().is_some_and(|d| stamp <= *d) {
            return None;
        }
        match &f.value {
            Val::Text(s) => Some(Cow::Borrowed(s)),
            Val::Uuid(b) => Some(Cow::Owned(codec::uuid_text(b))),
            _ => None,
        }
    }

    /// The ids of the visible records of one kind, sorted.
    pub(crate) fn ids(&self, kind: &str) -> Vec<String> {
        self.kind(kind)
            .filter(|(_, r)| r.visible())
            .map(|(id, _)| id.to_text())
            .collect()
    }

    /// The highest clock value of any write, so new writes come after it.
    pub(crate) fn max_hlc(&self) -> u64 {
        self.records
            .values()
            .flat_map(|r| {
                r.alive
                    .iter()
                    .chain(r.deleted.as_deref())
                    .chain(r.stamps.iter())
                    .map(|s| s.hlc)
            })
            .max()
            .unwrap_or(0)
    }

    /// The surviving state as snapshot operations, one record at a time, for
    /// compaction: deleted records and overwritten or deleted values are left
    /// out.
    pub(crate) fn snapshot(&self) -> impl Iterator<Item = Op> + '_ {
        self.records
            .iter()
            .filter(|(_, r)| r.visible())
            .map(|((kind, id), r)| {
                let mut fields: Vec<(String, Stamp, Value)> = r
                    .visible_fields()
                    .map(|(f, s)| (self.names.get(f.name).to_owned(), *s, f.value.to_value()))
                    .collect();
                fields.sort_unstable_by(|a, b| a.0.cmp(&b.0));
                Op::Snap {
                    kind: self.names.get(*kind).to_owned(),
                    id: id.to_text(),
                    alive: r.alive.expect("visible records are alive"),
                    fields,
                }
            })
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
