use proptest::prelude::*;
use serde_json::{Map, Value, json};

use super::*;

const DEV_A: [u8; 16] = [0xA; 16];

/// The batch in format 2, without padding, in a buffer of [`len_bound`].
fn encode(batch: &Batch) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let mut out = zeroize::Zeroizing::new(Vec::with_capacity(len_bound(batch)));
    encode_into(batch, &mut out)?;
    Ok(out)
}
const DEV_B: [u8; 16] = [0xB; 16];
const ID: &str = "0195f4c2-7a1b-7c3d-8e4f-123456789abc";

fn fields(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

fn stamp(hlc: u64, device: [u8; 16], seq: u64, index: u32) -> Stamp {
    Stamp {
        hlc,
        device,
        seq,
        index,
    }
}

/// Every kind of operation and value.
fn sample() -> Batch {
    Batch {
        hlc: (1_760_000_000_000 << 16) | 3,
        ops: vec![
            Op::Put {
                kind: "set".into(),
                id: ID.into(),
                fields: fields(json!({
                    "entry": "0195f4c2-7a1b-7c3d-8e4f-000000000001",
                    "reps": 5,
                    "weight_g": 100000,
                    "delta": -3,
                    "lowest": i64::MIN,
                    "highest": u64::MAX,
                    "ratio": 2.5,
                    "whole": 5.0,
                    "done": true,
                    "skipped": false,
                    "notes": null,
                    "text": "Grüße, \u{1F94A}",
                    "upper": "0195F4C2-7A1B-7C3D-8E4F-123456789ABC",
                })),
            },
            Op::Del {
                kind: "weight".into(),
                id: "profile".into(),
            },
            Op::Snap {
                kind: "_blob".into(),
                id: "abc_DEF-1".into(),
                alive: stamp(9, DEV_A, 4, 0),
                fields: vec![
                    ("a".into(), stamp(5, DEV_A, 2, 1), json!(1)),
                    ("b".into(), stamp(5, DEV_A, 2, 1), json!("two")),
                    ("c".into(), stamp(7, DEV_B, 9, 0), json!(null)),
                ],
            },
        ],
    }
}

/// Bytes for hand-made batches.
fn uv(v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    put_uv(&mut out, v);
    out
}

/// A batch of one put of `kind` "k" with id "i" and the given encoded
/// fields; `names` is the table.
fn one_put(names: &[&str], fields: &[u8], count: u64) -> Vec<u8> {
    let mut b = vec![0, 0]; // hlc 0, no devices
    b.extend(uv(names.len() as u64));
    for n in names {
        b.extend(uv(n.len() as u64));
        b.extend(n.as_bytes());
    }
    b.extend([1, PUT, 0, ID_TEXT, 1, b'i']); // one op: put, kind 0, id "i"
    b.extend(uv(count));
    b.extend(fields);
    b
}

#[test]
fn round_trip_keeps_every_kind_of_operation_and_value() {
    let decoded = decode(&encode(&sample()).unwrap()).unwrap();
    assert_eq!(decoded, sample());
    let Op::Put { fields, .. } = &decoded.ops[0] else {
        panic!("put");
    };
    // Numbers keep their kind: the app reads integers and floats differently.
    assert!(fields["reps"].is_u64());
    assert!(fields["delta"].is_i64());
    assert!(fields["whole"].is_f64());
    assert_eq!(fields["upper"], "0195F4C2-7A1B-7C3D-8E4F-123456789ABC");
}

#[test]
fn snapshots_store_one_stamp_per_group() {
    let snap = |distinct: bool| Batch {
        hlc: 1,
        ops: vec![Op::Snap {
            kind: "set".into(),
            id: "a".into(),
            alive: stamp(1 << 40, DEV_A, 1, 0),
            fields: (0..10u32)
                .map(|i| {
                    let index = if distinct { i } else { 0 };
                    (format!("f{i}"), stamp(1 << 40, DEV_A, 1, index), json!(i))
                })
                .collect(),
        }],
    };
    let one = encode(&snap(false)).unwrap().len();
    let ten = encode(&snap(true)).unwrap().len();
    // Each extra stamp costs its clock (6 bytes here), device, seq and index.
    assert!(ten >= one + 9 * 9, "{one} vs {ten}");
}

#[test]
fn uuids_take_sixteen_bytes() {
    let put = |id: &str, value: &str| Batch {
        hlc: 1,
        ops: vec![Op::Put {
            kind: "set".into(),
            id: id.into(),
            fields: fields(json!({ "entry": value })),
        }],
    };
    let uuids = encode(&put(ID, ID)).unwrap().len();
    let texts = encode(&put(&ID.to_uppercase(), &ID.to_uppercase()))
        .unwrap()
        .len();
    assert_eq!(texts - uuids, 2 * (37 - 16));
}

#[test]
fn format_2_is_much_smaller_than_json_for_a_snapshot() {
    let ops: Vec<Op> = (0..100u32)
        .map(|r| Op::Snap {
            kind: "set".into(),
            id: format!("0195f4c2-7a1b-7c3d-8e4f-{r:012x}"),
            alive: stamp(1 << 40, DEV_A, u64::from(r), 0),
            fields: [
                "entry",
                "order",
                "weight_g",
                "target_reps",
                "rest_planned_s",
                "predict_1rm",
                "reps",
                "done_ms",
                "rest_taken_s",
                "notes",
            ]
            .iter()
            .enumerate()
            .map(|(i, n)| {
                let s = stamp(
                    (1 << 40) + u64::from(r % 3),
                    DEV_A,
                    u64::from(r),
                    u32::from(i > 5),
                );
                (n.to_string(), s, json!(i * 1000))
            })
            .collect(),
        })
        .collect();
    let batch = Batch { hlc: 1, ops };
    let binary = encode(&batch).unwrap().len();
    let json = serde_json::to_vec(&batch).unwrap().len();
    assert!(
        binary * 4 < json,
        "binary {binary} bytes, JSON {json} bytes"
    );
}

#[test]
fn only_zero_padding_may_follow() {
    let mut b = encode(&sample()).unwrap().to_vec();
    b.extend([0; 100]);
    assert_eq!(decode(&b).unwrap(), sample());
    *b.last_mut().unwrap() = 1;
    assert_eq!(decode(&b), Err(bad()));
}

#[test]
fn every_truncation_is_refused() {
    let b = encode(&sample()).unwrap();
    for cut in 0..b.len() {
        assert!(decode(&b[..cut]).is_err(), "cut at {cut}");
    }
}

#[test]
fn varints_must_be_minimal_and_fit() {
    assert_eq!(
        decode(&[0, 0, 0, 0]).unwrap(),
        Batch {
            hlc: 0,
            ops: vec![]
        }
    );
    for b in [
        &[0x80, 0x00, 0, 0, 0][..], // zero in two bytes
        &[0x81, 0x00, 0, 0, 0],     // 1 with a zero group
        &[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0, 0, 0,
        ], // over 64 bits
        &[0x80; 11],                // too long
    ] {
        assert_eq!(decode(b), Err(bad()), "{b:?}");
    }
    let max = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0, 0, 0,
    ];
    assert_eq!(decode(&max).unwrap().hlc, u64::MAX);
}

#[test]
fn damaged_counts_indexes_and_tags_are_refused() {
    // A huge op count is refused before anything is allocated.
    assert_eq!(decode(&[0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0x0f]), Err(bad()));
    assert_eq!(decode(&[0, 0xff, 0x7f]), Err(bad()));
    // A name index outside the table.
    let mut field = uv(5);
    field.push(NULL);
    assert_eq!(decode(&one_put(&["k"], &field, 1)), Err(bad()));
    // Unknown tags: of a value, an id, an operation.
    assert_eq!(decode(&one_put(&["k", "f"], &[1, 9], 1)), Err(bad()));
    let mut b = one_put(&["k"], &[], 0);
    assert!(decode(&b).is_ok());
    let id_tag = b.len() - 4;
    b[id_tag] = 9;
    assert_eq!(decode(&b), Err(bad()));
    let mut b = one_put(&["k"], &[], 0);
    let op_tag = b.len() - 6;
    b[op_tag] = 9;
    assert_eq!(decode(&b), Err(bad()));
    // A device index outside the (empty) table, in a snapshot.
    let mut b = vec![0, 0, 1, 1, b'k', 1, SNAP, 0, ID_TEXT, 1, b'i'];
    b.extend([0, 0, 0, 0]); // alive: hlc 0, device 0, seq 0, index 0
    b.extend([0]); // no groups
    assert_eq!(decode(&b), Err(bad()));
}

#[test]
fn odd_values_and_names_are_refused() {
    let names = ["k", "f", "g"];
    let float = |x: f64| {
        let mut v = vec![1, FLOAT];
        v.extend(x.to_le_bytes());
        v
    };
    assert!(decode(&one_put(&names, &float(1.5), 1)).is_ok());
    assert_eq!(decode(&one_put(&names, &float(f64::NAN), 1)), Err(bad()));
    assert_eq!(
        decode(&one_put(&names, &float(f64::INFINITY), 1)),
        Err(bad())
    );
    // A UUID-shaped text must use the UUID form.
    let mut text = vec![1, TEXT];
    text.extend(uv(ID.len() as u64));
    text.extend(ID.as_bytes());
    assert_eq!(decode(&one_put(&names, &text, 1)), Err(bad()));
    // Not UTF-8.
    assert_eq!(
        decode(&one_put(&names, &[1, TEXT, 2, 0xff, 0xfe], 1)),
        Err(bad())
    );
    // A negative integer beyond i64.
    let mut neg = vec![1, NEGINT];
    neg.extend(uv(1 << 63));
    assert_eq!(decode(&one_put(&names, &neg, 1)), Err(bad()));
    // The same field twice.
    assert_eq!(decode(&one_put(&names, &[1, NULL, 1, TRUE], 2)), Err(bad()));
    // An empty or repeated name in the table, or a repeated device.
    assert_eq!(decode(&one_put(&["k", ""], &[], 0)), Err(bad()));
    assert_eq!(decode(&one_put(&["k", "k"], &[], 0)), Err(bad()));
    let devices = |ds: &[[u8; 16]]| {
        let mut b = vec![0, ds.len() as u8];
        ds.iter().for_each(|d| b.extend(d));
        b.extend([0, 0]);
        decode(&b)
    };
    assert!(devices(&[DEV_A, DEV_B]).is_ok());
    assert_eq!(devices(&[DEV_A, DEV_A]), Err(bad()));
    // A text id in UUID form, and an empty one.
    let mut b = vec![0, 0, 1, 1, b'k', 1, DEL, 0, ID_TEXT];
    b.extend(uv(ID.len() as u64));
    b.extend(ID.as_bytes());
    assert_eq!(decode(&b), Err(bad()));
    assert_eq!(
        decode(&[0, 0, 1, 1, b'k', 1, DEL, 0, ID_TEXT, 0]),
        Err(bad())
    );
}

#[test]
fn snapshot_groups_must_be_ordered_unique_and_non_empty() {
    // devices: [DEV_A]; names: k, f, g; one snap of kind 0, id "i".
    let snap = |groups: &[(u64, &[(u64, u8)])]| {
        let mut b = vec![0, 1];
        b.extend(DEV_A);
        b.extend([3, 1, b'k', 1, b'f', 1, b'g', 1, SNAP, 0, ID_TEXT, 1, b'i']);
        b.extend([9, 0, 0, 0]); // alive
        b.extend(uv(groups.len() as u64));
        for (hlc, fields) in groups {
            b.extend(uv(*hlc));
            b.extend([0, 0, 0]);
            b.extend(uv(fields.len() as u64));
            for (name, value) in *fields {
                b.extend(uv(*name));
                b.push(*value);
            }
        }
        b
    };
    let ok = decode(&snap(&[(1, &[(1, TRUE)]), (2, &[(2, FALSE)])])).unwrap();
    let Op::Snap { fields, .. } = &ok.ops[0] else {
        panic!("snap");
    };
    assert_eq!(fields.len(), 2);
    assert_eq!(
        decode(&snap(&[(2, &[(1, TRUE)]), (1, &[(2, FALSE)])])),
        Err(bad())
    );
    assert_eq!(
        decode(&snap(&[(1, &[(1, TRUE)]), (1, &[(2, FALSE)])])),
        Err(bad())
    );
    assert_eq!(
        decode(&snap(&[(1, &[(1, TRUE)]), (2, &[(1, FALSE)])])),
        Err(bad())
    );
    assert_eq!(decode(&snap(&[(1, &[])])), Err(bad()));
}

/// Tables are checked in linear time: a frame's worth of names (200,000 in
/// 800 KB) decodes at once. Comparing every pair would take 2·10¹⁰ string
/// comparisons.
#[test]
fn a_large_name_table_decodes_quickly() {
    const CHARS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let n = 200_000;
    let mut b = vec![0, 0];
    b.extend(uv(n as u64));
    for i in 0..n {
        let name = [CHARS[i / 3844], CHARS[i / 62 % 62], CHARS[i % 62]];
        b.extend(uv(3));
        b.extend(name);
    }
    b.push(0);
    assert!(b.len() < 1 << 20);
    let started = std::time::Instant::now();
    assert_eq!(decode(&b).unwrap().ops.len(), 0);
    // Generous, for valgrind and coverage runs.
    assert!(started.elapsed() < std::time::Duration::from_secs(30));
}

#[test]
fn nested_values_cant_be_encoded() {
    let batch = Batch {
        hlc: 1,
        ops: vec![Op::Put {
            kind: "set".into(),
            id: "a".into(),
            fields: fields(json!({"list": [1, 2]})),
        }],
    };
    assert_eq!(encode(&batch).unwrap_err(), Error::Internal("nested value"));
}

#[test]
fn golden_batch_v2() {
    let bytes = encode(&sample()).unwrap();
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/batch_v2.hex");
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(path, hex::encode(&bytes[..]) + "\n").unwrap();
    }
    let golden = hex::decode(std::fs::read_to_string(path).unwrap().trim()).unwrap();
    assert_eq!(hex::encode(&bytes[..]), hex::encode(&golden));
    assert_eq!(decode(&golden).unwrap(), sample());
}

// ---- Properties ---------------------------------------------------------------

fn arb_name() -> impl Strategy<Value = String> {
    prop::sample::select(vec!["a", "b", "reps", "weight_g", "notes", "x9"]).prop_map(String::from)
}

fn arb_id() -> impl Strategy<Value = String> {
    prop_oneof![
        any::<[u8; 16]>().prop_map(|b| uuid_text(&b)),
        "[a-zA-Z0-9_-]{1,64}",
    ]
}

fn arb_value() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<u64>().prop_map(|n| json!(n)),
        (i64::MIN..0).prop_map(|n| json!(n)),
        any::<f64>()
            .prop_filter("finite", |f| f.is_finite())
            .prop_map(|f| json!(f)),
        any::<[u8; 16]>().prop_map(|b| Value::String(uuid_text(&b))),
        ".{0,40}".prop_map(Value::String),
    ]
}

fn arb_stamp() -> impl Strategy<Value = Stamp> {
    (
        0u64..4,
        prop::sample::select(vec![DEV_A, DEV_B]),
        0u64..3,
        0u32..3,
    )
        .prop_map(|(hlc, device, seq, index)| stamp(hlc, device, seq, index))
}

fn arb_op() -> impl Strategy<Value = Op> {
    let kind = prop::sample::select(vec!["set", "session", "_blob"]).prop_map(String::from);
    prop_oneof![
        (
            kind.clone(),
            arb_id(),
            prop::collection::btree_map(arb_name(), arb_value(), 0..6)
        )
            .prop_map(|(kind, id, f)| Op::Put {
                kind,
                id,
                fields: f.into_iter().collect(),
            }),
        (kind.clone(), arb_id()).prop_map(|(kind, id)| Op::Del { kind, id }),
        (
            kind,
            arb_id(),
            arb_stamp(),
            prop::collection::btree_map(arb_name(), (arb_stamp(), arb_value()), 0..6)
        )
            .prop_map(|(kind, id, alive, f)| Op::Snap {
                kind,
                id,
                alive,
                fields: f.into_iter().map(|(n, (s, v))| (n, s, v)).collect(),
            }),
    ]
}

fn arb_batch() -> impl Strategy<Value = Batch> {
    (any::<u64>(), prop::collection::vec(arb_op(), 0..8)).prop_map(|(hlc, ops)| Batch { hlc, ops })
}

proptest! {
    #[test]
    fn arbitrary_batches_round_trip(batch in arb_batch()) {
        let bytes = encode(&batch).unwrap();
        prop_assert_eq!(decode(&bytes).unwrap(), batch.clone());
        // The bound used for splitting and for sizing the buffer holds, so
        // the buffer was never reallocated.
        let bound = len_bound(&batch);
        prop_assert!(bytes.len() <= bound, "{} > {}", bytes.len(), bound);
        prop_assert_eq!(bytes.capacity(), bound);
    }

    #[test]
    fn random_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..300)) {
        let _ = decode(&bytes);
    }

    #[test]
    fn damaged_encodings_never_panic(
        batch in arb_batch(),
        flips in prop::collection::vec((any::<prop::sample::Index>(), 1u8..=255), 1..4),
    ) {
        let mut bytes = encode(&batch).unwrap().to_vec();
        if bytes.is_empty() {
            return Ok(());
        }
        for (i, x) in flips {
            let i = i.index(bytes.len());
            bytes[i] ^= x;
        }
        // Whatever still decodes encodes back to a batch that decodes the same.
        if let Ok(b) = decode(&bytes) {
            prop_assert_eq!(decode(&encode(&b).unwrap()).unwrap(), b);
        }
    }
}
