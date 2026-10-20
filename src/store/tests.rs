use proptest::prelude::*;
use serde_json::json;

use super::*;

const DEV_A: [u8; 16] = [0xA; 16];
const DEV_B: [u8; 16] = [0xB; 16];

fn fields(v: serde_json::Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

fn put(kind: &str, id: &str, f: serde_json::Value) -> Op {
    Op::Put {
        kind: kind.into(),
        id: id.into(),
        fields: fields(f),
    }
}

fn del(kind: &str, id: &str) -> Op {
    Op::Del {
        kind: kind.into(),
        id: id.into(),
    }
}

fn batch(hlc: u64, ops: Vec<Op>) -> Batch {
    Batch { hlc, ops }
}

#[test]
fn partial_updates_keep_other_fields() {
    let mut s = Store::default();
    s.apply(
        &batch(
            1,
            vec![put("set", "s1", json!({"reps": 5, "weight_g": 100000}))],
        ),
        DEV_A,
        1,
    );
    s.apply(
        &batch(2, vec![put("set", "s1", json!({"reps": 6}))]),
        DEV_A,
        2,
    );
    let r = s.get("set", "s1").unwrap();
    assert_eq!(r.fields, fields(json!({"reps": 6, "weight_g": 100000})));
    // null clears a field.
    s.apply(
        &batch(3, vec![put("set", "s1", json!({"weight_g": null}))]),
        DEV_A,
        3,
    );
    assert_eq!(
        s.get("set", "s1").unwrap().fields,
        fields(json!({"reps": 6}))
    );
}

#[test]
fn deletion_hides_and_recreation_starts_fresh() {
    let mut s = Store::default();
    s.apply(
        &batch(1, vec![put("set", "s1", json!({"reps": 5, "note": "x"}))]),
        DEV_A,
        1,
    );
    s.apply(&batch(2, vec![del("set", "s1")]), DEV_A, 2);
    assert_eq!(s.get("set", "s1"), None);
    assert!(s.records("set").is_empty());
    // Undo: the app writes the record again; only what it writes is back.
    s.apply(
        &batch(3, vec![put("set", "s1", json!({"reps": 5}))]),
        DEV_A,
        3,
    );
    assert_eq!(
        s.get("set", "s1").unwrap().fields,
        fields(json!({"reps": 5}))
    );
}

#[test]
fn later_ops_in_one_batch_win() {
    let mut s = Store::default();
    s.apply(
        &batch(
            1,
            vec![
                put("w", "a", json!({"g": 1})),
                put("w", "a", json!({"g": 2})),
                del("w", "b"),
            ],
        ),
        DEV_A,
        1,
    );
    assert_eq!(s.get("w", "a").unwrap().fields["g"], 2);
}

#[test]
fn records_are_by_kind_and_sorted() {
    let mut s = Store::default();
    s.apply(
        &batch(
            7,
            vec![
                put("set", "b", json!({})),
                put("set", "a", json!({"x": 1})),
                put("sessio", "z", json!({})),
                put("setx", "c", json!({})),
            ],
        ),
        DEV_A,
        1,
    );
    let ids: Vec<String> = s.records("set").into_iter().map(|r| r.id).collect();
    assert_eq!(ids, ["a", "b"]);
    assert_eq!(s.max_hlc(), 7);
    assert!(s.records("none").is_empty());
}

#[test]
fn snapshot_drops_history_but_keeps_state_and_stamps() {
    let mut s = Store::default();
    s.apply(
        &batch(1, vec![put("set", "s1", json!({"reps": 5, "w": 1}))]),
        DEV_A,
        1,
    );
    s.apply(
        &batch(2, vec![put("set", "s1", json!({"reps": 6}))]),
        DEV_A,
        2,
    );
    s.apply(
        &batch(
            3,
            vec![put("set", "s2", json!({"secret": "deleted value"}))],
        ),
        DEV_A,
        3,
    );
    s.apply(&batch(4, vec![del("set", "s2")]), DEV_A, 4);
    let snap: Vec<Op> = s.snapshot().collect();
    let text = serde_json::to_string(&snap).unwrap();
    assert!(!text.contains("deleted value"));
    assert!(!text.contains("s2"));
    let c = s.compacted();
    assert_eq!(c.records("set"), s.records("set"));
    assert!(!c.needs_compaction());
    // Stamps survive, so a later write still compares correctly.
    let mut late = c.clone();
    late.apply(
        &batch(2, vec![put("set", "s1", json!({"reps": 99}))]),
        DEV_A,
        1,
    );
    assert_eq!(late.get("set", "s1").unwrap().fields["reps"], 6);
}

#[test]
fn validation() {
    let ok = Change::Put {
        kind: "set".into(),
        id: "0199a2b3-c4d5-7e6f-8a9b-0c1d2e3f4a5b".into(),
        fields: fields(json!({"reps": 5, "note": "ok", "flag": true, "gone": null})),
    };
    assert!(validate(std::slice::from_ref(&ok)).is_ok());
    let bad = |c: Change| validate(&[c]).unwrap_err();
    let put_with = |kind: &str, id: &str, f: serde_json::Value| Change::Put {
        kind: kind.into(),
        id: id.into(),
        fields: fields(f),
    };
    assert_eq!(
        bad(put_with("_blob", "a", json!({}))),
        Error::InvalidInput("record kind")
    );
    assert_eq!(
        bad(put_with("Set", "a", json!({}))),
        Error::InvalidInput("record kind")
    );
    assert_eq!(
        bad(put_with("set", "", json!({}))),
        Error::InvalidInput("record id")
    );
    assert_eq!(
        bad(put_with("set", "a b", json!({}))),
        Error::InvalidInput("record id")
    );
    assert_eq!(
        bad(put_with("set", "a", json!({"Reps": 1}))),
        Error::InvalidInput("field name")
    );
    assert_eq!(
        bad(put_with("set", "a", json!({"x": [1]}))),
        Error::InvalidInput("fields must be flat")
    );
    assert_eq!(
        bad(put_with("set", "a", json!({"x": {"y": 1}}))),
        Error::InvalidInput("fields must be flat")
    );
    let long = "x".repeat(MAX_STRING_BYTES + 1);
    assert_eq!(
        bad(put_with("set", "a", json!({ "x": long }))),
        Error::InvalidInput("text too long")
    );
    assert_eq!(
        validate(&[]).unwrap_err(),
        Error::InvalidInput("number of changes")
    );
}

#[test]
fn batch_json_round_trip_and_strictness() {
    let b = batch(
        42,
        vec![
            put("set", "a", json!({"reps": 5})),
            del("set", "b"),
            Op::Snap {
                kind: "set".into(),
                id: "c".into(),
                alive: Stamp {
                    hlc: 1,
                    device: DEV_A,
                    seq: 2,
                    index: 3,
                },
                fields: vec![(
                    "reps".into(),
                    Stamp {
                        hlc: 1,
                        device: DEV_B,
                        seq: 2,
                        index: 3,
                    },
                    json!(7),
                )],
            },
        ],
    );
    let text = serde_json::to_string(&b).unwrap();
    assert!(
        text.contains(r#"["reps",[1,"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",2,3],7]"#),
        "{text}"
    );
    assert_eq!(serde_json::from_str::<Batch>(&text).unwrap(), b);
    for bad in [
        r#"{"hlc":1,"ops":[],"extra":1}"#,
        r#"{"hlc":1,"ops":[{"op":"zap","kind":"a","id":"b"}]}"#,
        r#"{"hlc":1,"ops":[{"op":"snap","kind":"a","id":"b","alive":[1,"00",2,3],"fields":[]}]}"#,
    ] {
        assert!(serde_json::from_str::<Batch>(bad).is_err(), "{bad}");
    }
}

#[test]
fn compaction_is_needed_after_deletes_or_many_overwrites() {
    let mut s = Store::default();
    s.apply(&batch(1, vec![put("w", "a", json!({"g": 1}))]), DEV_A, 1);
    assert!(!s.needs_compaction());
    for i in 0..100 {
        s.apply(
            &batch(2 + i, vec![put("w", "a", json!({ "g": i }))]),
            DEV_A,
            2 + i,
        );
    }
    assert!(s.needs_compaction());
    let mut d = s.compacted();
    assert!(!d.needs_compaction());
    d.apply(&batch(500, vec![del("w", "a")]), DEV_A, 1);
    assert!(d.needs_compaction());
}

// ---- Merge properties --------------------------------------------------

fn arb_op() -> impl Strategy<Value = Op> {
    let kind = prop::sample::select(vec!["set", "weight"]);
    let id = prop::sample::select(vec!["a", "b", "c"]);
    let field = prop::sample::select(vec!["reps", "weight_g", "note"]);
    let value = prop_oneof![
        Just(Value::Null),
        (0i64..5).prop_map(Value::from),
        Just(json!("x"))
    ];
    prop_oneof![
        3 => (kind.clone(), id.clone(), prop::collection::vec((field, value), 0..3)).prop_map(|(k, i, fs)| Op::Put {
            kind: k.into(),
            id: i.into(),
            fields: fs.into_iter().map(|(f, v)| (f.to_string(), v)).collect(),
        }),
        1 => (kind, id).prop_map(|(k, i)| Op::Del { kind: k.into(), id: i.into() }),
    ]
}

/// Operations with distinct stamps from two devices, as sync will deliver them.
fn arb_history() -> impl Strategy<Value = Vec<(Op, Stamp)>> {
    prop::collection::vec((arb_op(), 0u64..20, prop::bool::ANY), 0..25).prop_map(|ops| {
        ops.into_iter()
            .enumerate()
            .map(|(i, (op, hlc, b))| {
                let stamp = Stamp {
                    hlc,
                    device: if b { DEV_B } else { DEV_A },
                    seq: i as u64,
                    index: 0,
                };
                (op, stamp)
            })
            .collect()
    })
}

fn visible(s: &Store) -> Vec<Record> {
    let mut all = s.records("set");
    all.extend(s.records("weight"));
    all
}

proptest! {
    #[test]
    fn order_and_duplicates_dont_matter(history in arb_history(), seed in any::<u64>()) {
        let mut in_order = Store::default();
        for (op, stamp) in &history {
            in_order.apply_op(op, *stamp);
        }
        // Shuffled (a deterministic Fisher-Yates from the seed) and every
        // operation twice.
        let mut shuffled: Vec<_> = history.iter().chain(history.iter()).cloned().collect();
        let mut x = seed | 1;
        for i in (1..shuffled.len()).rev() {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            shuffled.swap(i, (x % (i as u64 + 1)) as usize);
        }
        let mut other = Store::default();
        for (op, stamp) in &shuffled {
            other.apply_op(op, *stamp);
        }
        prop_assert_eq!(visible(&in_order), visible(&other));
    }

    #[test]
    fn a_compacted_store_shows_the_same_records(history in arb_history()) {
        let mut s = Store::default();
        for (op, stamp) in &history {
            s.apply_op(op, *stamp);
        }
        prop_assert_eq!(visible(&s.compacted()), visible(&s));
        // Replaying the snapshot through either journal format gives the
        // same, too.
        let batch = Batch { hlc: 99, ops: s.snapshot().collect() };
        for format in [journal::FORMAT_JSON, journal::FORMAT_BINARY] {
            let plaintext = journal::encode(format, &batch).unwrap();
            let mut replayed = Store::default();
            replayed.apply(&journal::decode(format, &plaintext).unwrap(), DEV_A, 1);
            prop_assert_eq!(visible(&replayed), visible(&s));
        }
    }

    #[test]
    fn a_deletion_hides_everything_written_before_it(history in arb_history()) {
        let mut s = Store::default();
        for (op, stamp) in &history {
            s.apply_op(op, *stamp);
        }
        let last = Stamp { hlc: 1000, device: DEV_A, seq: 1000, index: 0 };
        s.apply_op(&del("set", "a"), last);
        prop_assert_eq!(s.get("set", "a"), None);
    }
}

// ---- The compact store against MVP 1's (D55 (2)) -------------------------

/// Kind, id, alive stamp and fields of each record in a snapshot.
type Snapshot = Vec<(String, String, Stamp, Vec<(String, Stamp, Value)>)>;

/// MVP 1's store, kept as the reference: maps of strings and JSON values.
#[derive(Default)]
struct Model {
    records: BTreeMap<(String, String), ModelRecord>,
}

#[derive(Default)]
struct ModelRecord {
    alive: Option<Stamp>,
    deleted: Option<Stamp>,
    fields: BTreeMap<String, (Stamp, Value)>,
}

impl ModelRecord {
    fn visible(&self) -> bool {
        match (self.alive, self.deleted) {
            (Some(a), Some(d)) => a > d,
            (Some(_), None) => true,
            (None, _) => false,
        }
    }

    fn visible_fields(&self) -> Vec<(String, Stamp, Value)> {
        self.fields
            .iter()
            .filter(|(_, (s, v))| self.deleted.is_none_or(|d| *s > d) && !v.is_null())
            .map(|(n, (s, v))| (n.clone(), *s, v.clone()))
            .collect()
    }

    fn write(&mut self, name: &str, stamp: Stamp, value: &Value) {
        if self.fields.get(name).is_none_or(|(s, _)| *s < stamp) {
            self.fields.insert(name.to_owned(), (stamp, value.clone()));
        }
    }
}

impl Model {
    fn apply_op(&mut self, op: &Op, stamp: Stamp) {
        match op {
            Op::Put { kind, id, fields } => {
                let r = self.records.entry((kind.clone(), id.clone())).or_default();
                r.alive = r.alive.max(Some(stamp));
                fields.iter().for_each(|(n, v)| r.write(n, stamp, v));
            }
            Op::Del { kind, id } => {
                let r = self.records.entry((kind.clone(), id.clone())).or_default();
                r.deleted = r.deleted.max(Some(stamp));
            }
            Op::Snap {
                kind,
                id,
                alive,
                fields,
            } => {
                let r = self.records.entry((kind.clone(), id.clone())).or_default();
                r.alive = r.alive.max(Some(*alive));
                fields.iter().for_each(|(n, s, v)| r.write(n, *s, v));
            }
        }
    }

    fn records(&self, kind: &str) -> Vec<Record> {
        self.records
            .iter()
            .filter(|((k, _), r)| k == kind && r.visible())
            .map(|((k, id), r)| Record {
                kind: k.clone(),
                id: id.clone(),
                fields: r
                    .visible_fields()
                    .into_iter()
                    .map(|(n, _, v)| (n, v))
                    .collect(),
            })
            .collect()
    }

    fn snapshot(&self) -> Snapshot {
        self.records
            .iter()
            .filter(|(_, r)| r.visible())
            .map(|((k, id), r)| (k.clone(), id.clone(), r.alive.unwrap(), r.visible_fields()))
            .collect()
    }

    fn max_hlc(&self) -> u64 {
        self.records
            .values()
            .flat_map(|r| {
                r.alive
                    .iter()
                    .chain(r.deleted.iter())
                    .map(|s| s.hlc)
                    .chain(r.fields.values().map(|(s, _)| s.hlc))
                    .collect::<Vec<_>>()
            })
            .max()
            .unwrap_or(0)
    }
}

const KINDS: [&str; 3] = ["set", "weight", "_blob"];
const UUID_A: &str = "0195f4c2-7a1b-7c3d-8e4f-123456789abc";
const UUID_B: &str = "0195f4c2-7a1b-7c3d-8e4f-12345678a000";

fn arb_rich_id() -> impl Strategy<Value = String> {
    prop::sample::select(vec![
        "a",
        "b",
        "0195f4c2",
        "0195f4c2-7a1b-7c3d-8e4f-123456789abcd",
        UUID_A,
        UUID_B,
        "0195F4C2-7A1B-7C3D-8E4F-123456789ABC",
        "z",
    ])
    .prop_map(String::from)
}

fn arb_rich_value() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        prop_oneof![Just(0u64), Just(u64::MAX), 0u64..1000].prop_map(Value::from),
        prop_oneof![Just(i64::MIN), Just(-1i64), -1000i64..0].prop_map(Value::from),
        prop_oneof![Just(-0.0f64), Just(2.5), Just(5.0), Just(f64::MAX)].prop_map(Value::from),
        prop::sample::select(vec![
            "",
            "x",
            "Grüße",
            UUID_A,
            "0195F4C2-7A1B-7C3D-8E4F-123456789ABC"
        ])
        .prop_map(Value::from),
    ]
}

fn arb_rich_stamp() -> impl Strategy<Value = Stamp> {
    (0u64..6, any::<bool>(), 0u64..4, 0u32..3).prop_map(|(hlc, b, seq, index)| Stamp {
        hlc,
        device: if b { DEV_B } else { DEV_A },
        seq,
        index,
    })
}

fn arb_rich_op() -> impl Strategy<Value = Op> {
    let kind = prop::sample::select(KINDS.to_vec()).prop_map(String::from);
    let name = prop::sample::select(vec!["reps", "weight_g", "note", "entry", "a9"]);
    prop_oneof![
        3 => (kind.clone(), arb_rich_id(), prop::collection::btree_map(name.clone(), arb_rich_value(), 0..5))
            .prop_map(|(kind, id, f)| Op::Put {
                kind,
                id,
                fields: f.into_iter().map(|(n, v)| (n.to_owned(), v)).collect(),
            }),
        1 => (kind.clone(), arb_rich_id()).prop_map(|(kind, id)| Op::Del { kind, id }),
        2 => (kind, arb_rich_id(), arb_rich_stamp(),
              prop::collection::vec((name, arb_rich_stamp(), arb_rich_value()), 0..6))
            .prop_map(|(kind, id, alive, f)| Op::Snap {
                kind,
                id,
                alive,
                // Repeated names included: only a damaged batch holds them,
                // and the later stamp must still win.
                fields: f.into_iter().map(|(n, s, v)| (n.to_owned(), s, v)).collect(),
            }),
    ]
}

/// A snapshot as comparable tuples.
fn snapshot_of(s: &Store) -> Snapshot {
    let mut all: Vec<_> = s
        .snapshot()
        .map(|op| match &op {
            Op::Snap {
                kind,
                id,
                alive,
                fields,
            } => (kind.clone(), id.clone(), *alive, fields.clone()),
            _ => unreachable!("snapshots hold snapshot operations"),
        })
        .collect();
    all.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    all
}

proptest! {
    #[test]
    fn the_compact_store_behaves_like_mvp_1s(
        ops in prop::collection::vec((arb_rich_op(), arb_rich_stamp()), 0..40),
    ) {
        let mut s = Store::default();
        let mut m = Model::default();
        for (op, stamp) in &ops {
            s.apply_op(op, *stamp);
            m.apply_op(op, *stamp);
        }
        for kind in KINDS {
            let records = s.records(kind);
            prop_assert_eq!(&records, &m.records(kind));
            let ids: Vec<String> = records.iter().map(|r| r.id.clone()).collect();
            prop_assert_eq!(s.ids(kind), ids);
            for r in &records {
                let got = s.get(kind, &r.id);
                prop_assert_eq!(got.as_ref(), Some(r));
                prop_assert!(s.exists(kind, &r.id));
                for (name, value) in &r.fields {
                    let text = s.field_str(kind, &r.id, name);
                    prop_assert_eq!(text.as_deref(), value.as_str());
                }
            }
        }
        prop_assert_eq!(s.max_hlc(), m.max_hlc());
        let mut expected = m.snapshot();
        expected.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
        prop_assert_eq!(snapshot_of(&s), expected);
        prop_assert_eq!(snapshot_of(&s.compacted()), snapshot_of(&s));
        // No record keeps a stamp none of its fields uses.
        for r in s.records.values() {
            for (i, _) in r.stamps.iter().enumerate() {
                prop_assert!(r.fields.iter().any(|f| f.stamp as usize == i));
            }
            prop_assert!(r.fields.windows(2).all(|w| w[0].name < w[1].name));
        }
    }
}

#[test]
fn ids_sort_as_their_texts_do() {
    let mut texts = vec![
        "",
        "0",
        "0195f4c2-7a1b-7c3d-8e4f-123456789abc",
        "0195f4c2-7a1b-7c3d-8e4f-123456789abcd",
        "0195f4c2-7a1b-7c3d-8e4f-12345678a000",
        "0195f4c2-ffff-7c3d-8e4f-123456789abc",
        "0195f4c2-",
        "0195F4C2-7A1B-7C3D-8E4F-123456789ABC",
        "ffffffff-ffff-ffff-ffff-ffffffffffff",
        "g",
        "a",
    ];
    let mut ids: Vec<Id> = texts.iter().map(|t| Id::new(t)).collect();
    texts.sort();
    ids.sort();
    let back: Vec<String> = ids.iter().map(Id::to_text).collect();
    assert_eq!(back, texts);
    assert!(matches!(Id::new(UUID_A), Id::Uuid(_)));
    assert!(matches!(Id::new(&UUID_A.to_uppercase()), Id::Text(_)));
}

#[test]
fn values_keep_their_kind() {
    for v in [
        json!(null),
        json!(true),
        json!(0),
        json!(u64::MAX),
        json!(-1),
        json!(i64::MIN),
        json!(5.0),
        json!(-0.0),
        json!(UUID_A),
        json!(UUID_A.to_uppercase()),
        json!("Grüße"),
    ] {
        let back = Val::new(&v).to_value();
        assert_eq!(back, v);
        assert_eq!(
            (back.is_u64(), back.is_i64(), back.is_f64()),
            (v.is_u64(), v.is_i64(), v.is_f64())
        );
        assert_eq!(
            serde_json::to_string(&back).unwrap(),
            serde_json::to_string(&v).unwrap()
        );
    }
    assert!(matches!(Val::new(&json!(UUID_A)), Val::Uuid(_)));
}

#[test]
fn fields_and_stamps_are_small() {
    assert_eq!(std::mem::size_of::<Val>(), 24);
    assert_eq!(std::mem::size_of::<Field>(), 32);
    // A record rewritten whole keeps one stamp, however often.
    let mut s = Store::default();
    for i in 0..10u64 {
        let op = put(
            "set",
            UUID_A,
            json!({"entry": UUID_B, "reps": i, "weight_g": 100000, "note": null}),
        );
        s.apply(&batch(i, vec![op]), DEV_A, i);
    }
    let r = s.records.values().next().unwrap();
    assert_eq!((r.stamps.len(), r.fields.len()), (1, 4));
    assert_eq!(r.fields.capacity(), 4);
    // Room for the second stamp a rewrite briefly needs, not four.
    assert!(r.stamps.capacity() <= 2);
    assert_eq!(s.names.names.len(), 5);
}

#[test]
fn growing_a_record_keeps_its_fields() {
    let mut s = Store::default();
    for i in 0..40u64 {
        let op = put("set", "a", json!({ format!("f{i}"): i }));
        s.apply(&batch(i, vec![op]), DEV_A, i);
    }
    let r = s.get("set", "a").unwrap();
    assert_eq!(r.fields.len(), 40);
    assert!((0..40u64).all(|i| r.fields[&format!("f{i}")] == i));
}

#[test]
fn uuid_values_are_read_as_texts() {
    let mut s = Store::default();
    let op = put("_blob", "b", json!({"key": "ab".repeat(32), "of": UUID_A}));
    s.apply(&batch(1, vec![op]), DEV_A, 1);
    assert!(matches!(
        s.field_str("_blob", "b", "key"),
        Some(Cow::Borrowed(_))
    ));
    assert_eq!(s.field_str("_blob", "b", "of").as_deref(), Some(UUID_A));
    assert_eq!(s.field_str("_blob", "b", "none"), None);
    s.apply(&batch(2, vec![del("_blob", "b")]), DEV_A, 2);
    assert_eq!(s.field_str("_blob", "b", "key"), None);
}
