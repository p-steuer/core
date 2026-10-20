//! Batches in journal format 2 (D55): a compact binary encoding.
//!
//! ```text
//! batch = hlc:uv  devices:uv device[16]*  names:uv (len:uv utf8)*  ops:uv op*  zeros
//! op    = 1 kind:uv id fields:uv (name:uv value)*                        put
//!       | 2 kind:uv id                                                    del
//!       | 3 kind:uv id alive:stamp groups:uv (stamp fields:uv (name:uv value)*)*   snap
//! id    = 0 uuid[16] | 1 len:uv utf8
//! stamp = hlc:uv device:uv seq:uv index:uv
//! value = 0 null | 1 false | 2 true | 3 uv | 4 uv (stands for −1 − uv)
//!       | 5 f64 (little-endian) | 6 len:uv utf8 | 7 uuid[16]
//! uv    = unsigned LEB128, minimal, at most 10 bytes
//! ```
//!
//! Kinds and field names point into the batch's table of names, the devices
//! of snapshot stamps into its table of devices, so every batch decodes on
//! its own. A snapshot stores one stamp per group of fields written together
//! instead of one per field. Ids and texts in canonical UUID form (lowercase,
//! with hyphens) take 16 bytes and come back unchanged.
//!
//! Decoding is strict (the plaintext is authenticated before it gets here,
//! but a parser should never trust its input):
//! - counts are checked against the bytes left, indexes against the tables;
//! - the tables hold no empty names and no repeats;
//! - varints must be minimal, texts UTF-8, numbers finite;
//! - names are unique within a record, and groups come in increasing stamp
//!   order;
//! - a UUID-shaped id or text must use the UUID form;
//! - only zero padding may follow the batch.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::{Map, Number, Value};

use super::{Batch, MAX_STRING_BYTES, Op, Stamp, wipe};
use crate::{Error, Result};

const PUT: u8 = 1;
const DEL: u8 = 2;
const SNAP: u8 = 3;
const ID_UUID: u8 = 0;
const ID_TEXT: u8 = 1;
const NULL: u8 = 0;
const FALSE: u8 = 1;
const TRUE: u8 = 2;
const UINT: u8 = 3;
const NEGINT: u8 = 4;
const FLOAT: u8 = 5;
const TEXT: u8 = 6;
const UUID: u8 = 7;
/// The longest kind, field name or record id the format takes.
const MAX_NAME: usize = 255;
/// The most bytes a varint takes.
const UV: usize = 10;

fn bad() -> Error {
    Error::Damaged("journal batch")
}

// ---- Encoding ---------------------------------------------------------------

fn put_uv(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let low = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}

fn put_text(out: &mut Vec<u8>, s: &str) {
    put_uv(out, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

/// The 16 bytes of a text in canonical UUID form: 8-4-4-4-12 lowercase hex
/// digits.
fn uuid_bytes(s: &str) -> Option<[u8; 16]> {
    let b = s.as_bytes();
    if b.len() != 36 {
        return None;
    }
    let mut out = [0u8; 16];
    let mut n = 0;
    for (i, &c) in b.iter().enumerate() {
        if matches!(i, 8 | 13 | 18 | 23) {
            if c != b'-' {
                return None;
            }
            continue;
        }
        let digit = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => return None,
        };
        out[n / 2] |= if n % 2 == 0 { digit << 4 } else { digit };
        n += 1;
    }
    Some(out)
}

fn uuid_text(b: &[u8; 16]) -> String {
    let hex = super::hex16(b);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

fn put_id(out: &mut Vec<u8>, id: &str) {
    match uuid_bytes(id) {
        Some(b) => {
            out.push(ID_UUID);
            out.extend_from_slice(&b);
        }
        None => {
            out.push(ID_TEXT);
            put_text(out, id);
        }
    }
}

fn put_value(out: &mut Vec<u8>, v: &Value) -> Result<()> {
    match v {
        Value::Null => out.push(NULL),
        Value::Bool(false) => out.push(FALSE),
        Value::Bool(true) => out.push(TRUE),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                out.push(UINT);
                put_uv(out, u);
            } else if let Some(i) = n.as_i64() {
                // Only negative numbers get here: -1 - i can't overflow.
                out.push(NEGINT);
                put_uv(out, (-1 - i) as u64);
            } else {
                let f = n.as_f64().ok_or(Error::Internal("number"))?;
                out.push(FLOAT);
                out.extend_from_slice(&f.to_le_bytes());
            }
        }
        Value::String(s) => match uuid_bytes(s) {
            Some(b) => {
                out.push(UUID);
                out.extend_from_slice(&b);
            }
            None => {
                out.push(TEXT);
                put_text(out, s);
            }
        },
        Value::Array(_) | Value::Object(_) => return Err(Error::Internal("nested value")),
    }
    Ok(())
}

/// The names and devices of one batch, numbered in order of first use.
#[derive(Default)]
struct Tables<'a> {
    names: Vec<&'a str>,
    name_at: HashMap<&'a str, u64>,
    devices: Vec<[u8; 16]>,
    device_at: HashMap<[u8; 16], u64>,
}

impl<'a> Tables<'a> {
    fn name(&mut self, s: &'a str) {
        if !self.name_at.contains_key(s) {
            self.name_at.insert(s, self.names.len() as u64);
            self.names.push(s);
        }
    }

    fn device(&mut self, d: [u8; 16]) {
        if !self.device_at.contains_key(&d) {
            self.device_at.insert(d, self.devices.len() as u64);
            self.devices.push(d);
        }
    }

    fn put_name(&self, out: &mut Vec<u8>, s: &str) {
        put_uv(out, self.name_at[s]);
    }

    fn put_stamp(&self, out: &mut Vec<u8>, s: &Stamp) {
        put_uv(out, s.hlc);
        put_uv(out, self.device_at[&s.device]);
        put_uv(out, s.seq);
        put_uv(out, u64::from(s.index));
    }
}

/// A snapshot's fields grouped by the stamp they were written with, in stamp
/// order, each group sorted by name.
fn groups(fields: &[(String, Stamp, Value)]) -> BTreeMap<Stamp, Vec<(&str, &Value)>> {
    let mut g: BTreeMap<Stamp, Vec<(&str, &Value)>> = BTreeMap::new();
    for (name, stamp, value) in fields {
        g.entry(*stamp).or_default().push((name.as_str(), value));
    }
    for fs in g.values_mut() {
        fs.sort_by(|a, b| a.0.cmp(b.0));
    }
    g
}

/// An upper bound for the batch's encoded size, so buffers can be sized up
/// front: growing one would leave a copy of the plaintext behind, unwiped.
pub(crate) fn len_bound(batch: &Batch) -> usize {
    4 * UV + batch.ops.iter().map(op_len).sum::<usize>()
}

/// Appends the batch in format 2, without padding. `out` needs room for
/// [`len_bound`] more bytes.
pub(crate) fn encode_into(batch: &Batch, out: &mut Vec<u8>) -> Result<()> {
    let mut t = Tables::default();
    for op in &batch.ops {
        match op {
            Op::Put { kind, fields, .. } => {
                t.name(kind);
                fields.keys().for_each(|n| t.name(n));
            }
            Op::Del { kind, .. } => t.name(kind),
            Op::Snap {
                kind,
                alive,
                fields,
                ..
            } => {
                t.name(kind);
                t.device(alive.device);
                for (n, s, _) in fields {
                    t.name(n);
                    t.device(s.device);
                }
            }
        }
    }
    put_uv(out, batch.hlc);
    put_uv(out, t.devices.len() as u64);
    for d in &t.devices {
        out.extend_from_slice(d);
    }
    put_uv(out, t.names.len() as u64);
    for n in &t.names {
        put_text(out, n);
    }
    put_uv(out, batch.ops.len() as u64);
    for op in &batch.ops {
        match op {
            Op::Put { kind, id, fields } => {
                out.push(PUT);
                t.put_name(out, kind);
                put_id(out, id);
                put_uv(out, fields.len() as u64);
                for (n, v) in fields {
                    t.put_name(out, n);
                    put_value(out, v)?;
                }
            }
            Op::Del { kind, id } => {
                out.push(DEL);
                t.put_name(out, kind);
                put_id(out, id);
            }
            Op::Snap {
                kind,
                id,
                alive,
                fields,
            } => {
                out.push(SNAP);
                t.put_name(out, kind);
                put_id(out, id);
                t.put_stamp(out, alive);
                let groups = groups(fields);
                put_uv(out, groups.len() as u64);
                for (stamp, fs) in &groups {
                    t.put_stamp(out, stamp);
                    put_uv(out, fs.len() as u64);
                    for (n, v) in fs {
                        t.put_name(out, n);
                        put_value(out, v)?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn name_len(s: &str) -> usize {
    // Its index, plus its entry in the table as if it were new.
    UV + UV + s.len()
}

fn value_len(v: &Value) -> usize {
    1 + match v {
        Value::String(s) => UV + s.len(),
        Value::Number(_) => UV,
        _ => 0,
    }
}

/// A stamp, with its device as if new to the table.
const STAMP_LEN: usize = 4 * UV + 16;

/// An upper bound for one snapshot field's encoded size, its stamp counted
/// as if it had a group of its own.
pub(crate) fn field_len(field: &(String, Stamp, Value)) -> usize {
    STAMP_LEN + UV + name_len(&field.0) + value_len(&field.2)
}

/// An upper bound for an operation's encoded size, its names and devices
/// counted as if new to the tables, so batches can be split without encoding
/// them.
pub(crate) fn op_len(op: &Op) -> usize {
    let head = |kind: &str, id: &str| 1 + name_len(kind) + 1 + UV + id.len();
    match op {
        Op::Put { kind, id, fields } => {
            head(kind, id)
                + UV
                + fields
                    .iter()
                    .map(|(n, v)| name_len(n) + value_len(v))
                    .sum::<usize>()
        }
        Op::Del { kind, id } => head(kind, id),
        Op::Snap {
            kind, id, fields, ..
        } => head(kind, id) + STAMP_LEN + UV + fields.iter().map(field_len).sum::<usize>(),
    }
}

// ---- Decoding ---------------------------------------------------------------

struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8> {
        let (&x, rest) = self.b.split_first().ok_or_else(bad)?;
        self.b = rest;
        Ok(x)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.b.len() {
            return Err(bad());
        }
        let (head, rest) = self.b.split_at(n);
        self.b = rest;
        Ok(head)
    }

    fn uuid(&mut self) -> Result<[u8; 16]> {
        Ok(self.take(16)?.try_into().expect("16 bytes"))
    }

    fn uv(&mut self) -> Result<u64> {
        let mut v = 0u64;
        for i in 0..UV {
            let b = self.byte()?;
            let bits = u64::from(b & 0x7f);
            if i == UV - 1 && bits > 1 {
                return Err(bad());
            }
            v |= bits << (7 * i);
            if b & 0x80 == 0 {
                // A final zero group (other than a lone zero) isn't minimal.
                if i > 0 && b == 0 {
                    return Err(bad());
                }
                return Ok(v);
            }
        }
        Err(bad())
    }

    /// A count of items that each take at least `min` bytes, so a damaged
    /// count can't make us reserve memory out of proportion to the input.
    fn count(&mut self, min: usize) -> Result<usize> {
        let n = self.uv()?;
        if n > (self.b.len() / min) as u64 {
            return Err(bad());
        }
        Ok(n as usize)
    }

    fn text(&mut self, max: usize) -> Result<String> {
        let n = self.uv()?;
        if n > max as u64 {
            return Err(bad());
        }
        let bytes = self.take(n as usize)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| bad())
    }

    fn name(&mut self, names: &[String]) -> Result<String> {
        let i = self.uv()?;
        usize::try_from(i)
            .ok()
            .and_then(|i| names.get(i))
            .cloned()
            .ok_or_else(bad)
    }

    fn id(&mut self) -> Result<String> {
        match self.byte()? {
            ID_UUID => Ok(uuid_text(&self.uuid()?)),
            ID_TEXT => {
                let s = self.text(MAX_NAME)?;
                if s.is_empty() || uuid_bytes(&s).is_some() {
                    return Err(bad());
                }
                Ok(s)
            }
            _ => Err(bad()),
        }
    }

    fn stamp(&mut self, devices: &[[u8; 16]]) -> Result<Stamp> {
        let hlc = self.uv()?;
        let device = usize::try_from(self.uv()?)
            .ok()
            .and_then(|i| devices.get(i))
            .copied()
            .ok_or_else(bad)?;
        let seq = self.uv()?;
        let index = u32::try_from(self.uv()?).map_err(|_| bad())?;
        Ok(Stamp {
            hlc,
            device,
            seq,
            index,
        })
    }

    fn value(&mut self) -> Result<Value> {
        Ok(match self.byte()? {
            NULL => Value::Null,
            FALSE => Value::Bool(false),
            TRUE => Value::Bool(true),
            UINT => Value::Number(Number::from(self.uv()?)),
            NEGINT => {
                let n = self.uv()?;
                let n = i64::try_from(n).map_err(|_| bad())?;
                Value::Number(Number::from(-1 - n))
            }
            FLOAT => {
                let bits = u64::from_le_bytes(self.take(8)?.try_into().expect("8 bytes"));
                Value::Number(Number::from_f64(f64::from_bits(bits)).ok_or_else(bad)?)
            }
            TEXT => {
                let s = self.text(MAX_STRING_BYTES)?;
                if uuid_bytes(&s).is_some() {
                    return Err(bad());
                }
                Value::String(s)
            }
            UUID => Value::String(uuid_text(&self.uuid()?)),
            _ => return Err(bad()),
        })
    }

    /// Operations are filled in place, so if a later part is damaged,
    /// dropping the operation wipes the values read so far.
    fn op(&mut self, names: &[String], devices: &[[u8; 16]]) -> Result<Op> {
        let tag = self.byte()?;
        let kind = self.name(names)?;
        let id = self.id()?;
        match tag {
            PUT => {
                let mut op = Op::Put {
                    kind,
                    id,
                    fields: Map::new(),
                };
                if let Op::Put { fields, .. } = &mut op {
                    self.fields(names, fields)?;
                }
                Ok(op)
            }
            DEL => Ok(Op::Del { kind, id }),
            SNAP => {
                let alive = self.stamp(devices)?;
                let mut op = Op::Snap {
                    kind,
                    id,
                    alive,
                    fields: Vec::new(),
                };
                if let Op::Snap { fields, .. } = &mut op {
                    self.groups(names, devices, fields)?;
                }
                Ok(op)
            }
            _ => Err(bad()),
        }
    }

    /// A put's fields.
    fn fields(&mut self, names: &[String], fields: &mut Map<String, Value>) -> Result<()> {
        let n = self.count(2)?;
        for _ in 0..n {
            let name = self.name(names)?;
            let value = self.value()?;
            if let Some(mut repeated) = fields.insert(name, value) {
                wipe(&mut repeated);
                return Err(bad());
            }
        }
        Ok(())
    }

    /// A snapshot's groups of fields, which it keeps sorted by name.
    fn groups(
        &mut self,
        names: &[String],
        devices: &[[u8; 16]],
        fields: &mut Vec<(String, Stamp, Value)>,
    ) -> Result<()> {
        let groups = self.count(4 + 1 + 2)?;
        let mut previous: Option<Stamp> = None;
        for _ in 0..groups {
            let stamp = self.stamp(devices)?;
            if previous.is_some_and(|p| p >= stamp) {
                return Err(bad());
            }
            previous = Some(stamp);
            let n = self.count(2)?;
            if n == 0 {
                return Err(bad());
            }
            for _ in 0..n {
                let name = self.name(names)?;
                let value = self.value()?;
                fields.push((name, stamp, value));
            }
        }
        fields.sort_by(|a, b| a.0.cmp(&b.0));
        if fields.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(bad());
        }
        Ok(())
    }
}

/// A batch from a frame's plaintext in format 2, padding included.
pub(crate) fn decode(bytes: &[u8]) -> Result<Batch> {
    let mut r = Reader { b: bytes };
    let hlc = r.uv()?;
    let n = r.count(16)?;
    let mut devices = Vec::with_capacity(n);
    for _ in 0..n {
        devices.push(r.uuid()?);
    }
    let mut seen = HashSet::with_capacity(devices.len());
    if !devices.iter().all(|d| seen.insert(d)) {
        return Err(bad());
    }
    let n = r.count(2)?;
    let mut names = Vec::with_capacity(n);
    for _ in 0..n {
        names.push(r.text(MAX_NAME)?);
    }
    let mut seen = HashSet::with_capacity(names.len());
    if !names
        .iter()
        .all(|s| !s.is_empty() && seen.insert(s.as_str()))
    {
        return Err(bad());
    }
    let n = r.count(3)?;
    let mut ops = Vec::with_capacity(n);
    for _ in 0..n {
        ops.push(r.op(&names, &devices)?);
    }
    if r.b.iter().any(|&b| b != 0) {
        return Err(bad());
    }
    Ok(Batch { hlc, ops })
}

#[cfg(test)]
mod tests;
