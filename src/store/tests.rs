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
    let snap = s.snapshot();
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
        let batch = Batch { hlc: 99, ops: s.snapshot() };
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
