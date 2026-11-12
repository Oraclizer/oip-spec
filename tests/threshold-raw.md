# THRESHOLD signature comparison

`scripts/check-threshold-raw.py` compares the pinned THRESHOLD signature-step
model with the configured Rust and Go receivers on the 22 raw Packets in
[`vectors/threshold-raw/input.jsonl`](vectors/threshold-raw/input.jsonl).
The model takes the recorded Ed25519 results in
[`primitive-observations.jsonl`](vectors/threshold-raw/primitive-observations.jsonl)
(22 rows) and [`key-observations.json`](vectors/threshold-raw/key-observations.json)
(3 keys) as inputs. Rust and Go run their own verifiers on the same bytes.
CI runs the comparison in the Go job of [`tests.yml`](../.github/workflows/tests.yml):

```bash
python3 scripts/check-threshold-raw.py --polyml target/polyml-userspace/bin/poly --output target/threshold-raw
```

The threshold identity returns six ASCII fields. The final field is the
`runtime_source_hash` in [the threshold lock](threshold-raw-artifact.lock.json),
which the typed transport and full response locks share.

```text
1
intinf-threshold-raw-v1
wire-v6-threshold-raw-observed-primitives
OIP_Threshold_Raw_ABI.threshold_raw_packet
HOL-Library.Code_Target_Nat
<runtime source fingerprint>
```

The lock pins the model, driver, origin and diagnostics files by Git blob and
SHA-256, and the three input files by SHA-256 and row count.

The check fails when the case order or coverage differs, when either
implementation reports Packet bytes other than the input, when the Rust or Go
signature step differs from the model, or when the attestation call, the
retained transport binding or the transport outcome differs from the replay
rule for these inputs. For an accepted Packet the model's result also fixes
the selected group, the signer identifiers, the Core and the signing preimage.

A pass is bounded evidence on these inputs. Ed25519 enters the model as
recorded results, so the comparison does not establish the Ed25519 primitive
or general implementation refinement.
