"""Software protocol tests only; no source/model/cryptographic execution."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from model_diagnostics import load_allowlist, split_exact
from reference_execution_contract import ROOT, compare_financial, financial_protocol, financial_projection, inputs, sha
from reference_model_artifact import FINANCIAL_IDENTITY, read_reference_lock, require_bound
from wire_model_artifact import read_lock


class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture_parent = ROOT / "target/software-contract-fixtures"
        cls.fixture_parent.mkdir(parents=True, exist_ok=True)
        cls.temp = Path(tempfile.mkdtemp(prefix="reference-", dir=cls.fixture_parent)).absolute()
        if not cls.temp.is_relative_to(cls.fixture_parent.absolute()):
            raise ValueError("Software fixture directory escaped the intended target")
        cls.contract = json.loads((ROOT / "tests/reference-replay.contract.json").read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls):
        if not cls.temp.is_relative_to(cls.fixture_parent.absolute()) or cls.temp == cls.fixture_parent.absolute():
            raise ValueError("Refusing an unexpected software fixture cleanup path")
        shutil.rmtree(cls.temp)

    def write_allowlist(self, allowed, model="a" * 64):
        path = self.temp / "diagnostics.json"
        path.write_text(json.dumps({"schema": "oip-compiler-diagnostics-v1", "model_sha256": model,
            "driver_sha256": "b" * 64, "allowed": allowed}), encoding="utf-8")
        return path

    def test_declared_input_scopes_and_input_only_serializer(self):
        _, rows = inputs(self.contract)
        _, same = inputs(self.contract, "same_cut_input")
        protocol, selected = financial_protocol(rows)
        self.assertEqual((len(rows), len(same), len(protocol.splitlines())), (15, 3, 8))
        self.assertEqual([row["id"] for row in selected], self.contract["financial_conformance"]["selected_ids"])
        poisoned = deepcopy(rows)
        for row in poisoned:
            row["unused_observation"] = {"source_afterstate": "never serialized"}
        self.assertEqual(financial_protocol(poisoned), (protocol, selected))

    def test_source_output_field_cannot_be_an_accepted_input(self):
        _, rows = inputs(self.contract)
        poisoned = deepcopy(rows)
        poisoned[1]["input"]["source_snapshot"] = {"expected_outcome": "pass"}
        raw = b"".join((json.dumps(row) + "\n").encode() for row in poisoned)
        path = self.temp / "poisoned.jsonl"
        path.write_bytes(raw)
        contract = deepcopy(self.contract)
        contract["input"]["path"] = str(path.relative_to(ROOT))
        contract["input"]["sha256"] = sha(raw)
        with self.assertRaises(ValueError):
            inputs(contract)

    def test_unbound_transport_fails(self):
        lock = json.loads((ROOT / "tests/model-artifact.lock.json").read_text(encoding="utf-8"))
        lock["binding_status"] = "unbound"
        path = self.temp / "unbound-transport.lock.json"
        path.write_text(json.dumps(lock), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "unbound"):
            read_lock(path)

    def test_unbound_reference_capabilities_fail(self):
        lock = read_reference_lock(ROOT / "tests/reference-models.lock.json")
        for name in ["financial", "full", "same-cut"]:
            lock["models"][name]["binding_status"] = "unbound"
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "unbound"):
                require_bound(lock, name, "0" * 64)

    def test_bound_label_cannot_supply_unreceived_full_engine(self):
        lock = read_reference_lock(ROOT / "tests/reference-models.lock.json")
        row = lock["models"]["full"]
        row.update(binding_status="bound", runtime_source_hash="0" * 64, verified_export_sha256="a" * 64, kernel_inputs_sha256="b" * 64, engine=None)
        with self.assertRaisesRegex(ValueError, "have not been received"):
            require_bound(lock, "full", "0" * 64)

    def test_exact_registered_diagnostic_is_separate(self):
        lines = ["{model_path}:736: warning: Matches are not exhaustive.", "Found near", "  fun nth (x :: xs) n = (...)"]
        path = self.write_allowlist([{"stream": "stdout", "lines": lines, "maximum": 1}])
        allowed = load_allowlist(path, "a" * 64, "b" * 64)
        raw = ("\n".join([line.replace("{model_path}", "model.ML") for line in lines]) + "\nOIP-UNIT\trow\n").encode()
        protocol, receipt = split_exact(raw, b"", prefixes=["OIP-UNIT"], allowlist=allowed, model_path="model.ML")
        self.assertEqual(protocol, ["OIP-UNIT\trow"])
        self.assertEqual(len(receipt["diagnostic_blocks"]), 1)
        self.assertEqual(receipt["unknown_lines_ignored"], 0)

    def test_unknown_output_is_not_ignored(self):
        for raw in [b"unknown warning\n", b"val ignored = ...\n", b"OIP-PENDING\trow\n", b"\n"]:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                split_exact(raw, b"", prefixes=["OIP-UNIT"])

    def test_unknown_stderr_is_not_ignored(self):
        with self.assertRaises(ValueError):
            split_exact(b"OIP-UNIT\trow\n", b"new diagnostic\n", prefixes=["OIP-UNIT"])

    def test_diagnostic_pin_cannot_bind_other_model(self):
        path = self.write_allowlist([])
        with self.assertRaisesRegex(ValueError, "different model"):
            load_allowlist(path, "c" * 64, "b" * 64)

    def test_diagnostic_cannot_consume_protocol(self):
        path = self.write_allowlist([{"stream": "stdout", "lines": ["OIP-FINITE\trow"], "maximum": 1}])
        with self.assertRaises(ValueError):
            load_allowlist(path, "a" * 64, "b" * 64)

    def test_changed_warning_and_repeat_are_errors(self):
        path = self.write_allowlist([{"stream": "stdout", "lines": ["exact warning"], "maximum": 1}])
        allowed = load_allowlist(path, "a" * 64, "b" * 64)
        for raw in [b"exact warning plus unknown\n", b"exact warning\nexact warning\n"]:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                split_exact(raw, b"", prefixes=["OIP-UNIT"], allowlist=allowed)

    def synthetic_financial(self):
        identity = FINANCIAL_IDENTITY + ["0" * 64]
        metadata = [0, 2, 17, 7, 10, 9, 9, 0, 0]
        product = {"cut": {"revision": 0}, "source_pool": {"value": {"Units": 10}},
            "accounts": [{"account": {"endpoint": 0, "asset": 17, "owner": 7}, "account_balance": {"value": {"Units": 10}}}],
            "pending": 0, "phase": None, "retained_image": {"authority": {"primary": {"journal": []}}},
            "ledger": {"state": {"reservations": []}}}
        observation = {"after": {"product": product}, "response": {"verified": {"category": "known", "code": 1, "commit": None}}}
        bindings = [{"id": "unit.0", "kind": "SEED", "metadata": metadata}, {"id": "unit.1", "kind": "STEP"}]
        source = {("unit.0", "after"): observation, ("unit.1", "after"): observation}
        lines = ["\t".join(["OIP-FINANCIAL-MODEL"] + identity),
                 "OIP-FINITE\tunit.0\tSEED\t0,10,10,0,0,0,0", "OIP-FINITE\tunit.1\tSTEP\t0,1,0,0,0,10,10,0,0,0,0"]
        return lines, identity, bindings, source

    def test_financial_parser_rejects_pending_and_bad_order(self):
        lines, identity, bindings, source = self.synthetic_financial()
        self.assertTrue(all(not row["differences"] for row in compare_financial(lines, identity, bindings, source)))
        for bad in [lines[1:], [lines[0], lines[2], lines[1]], lines + [lines[1]],
                    [lines[0], lines[1], lines[2].replace("STEP\t0,", "STEP\t~1,")]]:
            with self.subTest(lines=bad), self.assertRaises(ValueError):
                compare_financial(bad, identity, bindings, source)

    def test_unknown_source_response_cannot_match(self):
        lines, identity, bindings, source = self.synthetic_financial()
        source[("unit.1", "after")]["response"]["verified"]["category"] = "unknown"
        with self.assertRaises(ValueError):
            compare_financial(lines, identity, bindings, source)


if __name__ == "__main__":
    unittest.main()
