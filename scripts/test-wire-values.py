"""Pure software protocol tests; no Rust, Go, SML, crypto or proof execution."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from wire_values import ROOT,schema,typed_tree,validate_result,validate_results,require_equal

def module(name,filename):
    spec=importlib.util.spec_from_file_location(name,ROOT/"scripts"/filename);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
adapter=module("typed_adapter_contract","jsonl-mirror-adapter.py")
response=module("response_contract","response_result_codec.py")

class WireValueContracts(unittest.TestCase):
    def setUp(self):
        self.schema=schema()
        self.key=["200","4","0","7","0","0","0","7","1","16"]+["0"]*16
        self.typed=["19","2","0","3","0","200"]
        self.row={"id":"unit","verdict":"accept:first","retained_binding":"aa","reencoded_core_hex":"aa",
            "signing_preimage_hex":"bb","transport_key_ir":self.key,"typed_operand_ir":self.typed}
    def test_complete_typed_observation(self):
        self.assertEqual(validate_result(self.row,self.schema),self.row)
    def test_accept_binding_only_is_incomplete(self):
        old={key:self.row[key] for key in ["id","verdict","retained_binding"]}
        with self.assertRaises(ValueError):validate_result(old,self.schema)
    def test_accept_bool_or_raw_bytes_cannot_replace_typed_value(self):
        for replacement in [["0","1"],["1","2","1","2"],[]]:
            row=deepcopy(self.row);row["typed_operand_ir"]=replacement
            with self.subTest(value=replacement),self.assertRaises(ValueError):validate_result(row,self.schema)
    def test_different_typed_field_breaks_equal_outer_acceptance(self):
        other=deepcopy(self.row);other["typed_operand_ir"][-1]="201"
        validate_result(other,self.schema)
        self.assertEqual(other["verdict"],self.row["verdict"])
        self.assertEqual(other["retained_binding"],self.row["retained_binding"])
        with self.assertRaises(ValueError):require_equal([self.row],[other])
    def test_preimage_key_and_reencoding_are_not_ignored(self):
        for field in ["reencoded_core_hex","signing_preimage_hex","transport_key_ir"]:
            other=deepcopy(self.row)
            if field.endswith("hex"):other[field]="cc"
            else:other[field][3]="8"
            with self.subTest(field=field),self.assertRaises(ValueError):require_equal([self.row],[other])
    def test_bad_tlv_shape_token_or_arity_fails(self):
        for tokens in [["19","1","0","3"],["19","2","0","03","0","4"],["999","0"],self.typed+["0"],["1","1","256"]]:
            with self.subTest(tokens=tokens),self.assertRaises(ValueError):typed_tree(tokens,self.schema)
    def test_refusal_cannot_carry_fabricated_values(self):
        row=deepcopy(self.row);row["verdict"]=70
        with self.assertRaises(ValueError):validate_result(row,self.schema)
        for field in ["reencoded_core_hex","signing_preimage_hex","transport_key_ir","typed_operand_ir"]:row[field]=None
        validate_result(row,self.schema)
    def test_unknown_pending_is_not_a_match(self):
        for verdict in ["pending","Unsupported",True,-1,999]:
            row=deepcopy(self.row);row["verdict"]=verdict
            with self.subTest(verdict=verdict),self.assertRaises(ValueError):validate_result(row,self.schema)
    def test_order_count_and_duplicate_identity_fails(self):
        for rows,ids in [([self.row,self.row],["unit","unit"]),([self.row],["missing"]),([],["unit"])]:
            with self.subTest(ids=ids),self.assertRaises(ValueError):validate_results(rows,ids,self.schema)
    def test_typed_model_ten_field_protocol(self):
        line="\t".join(["OIP-MIRROR","encoded","0","1","170","1",",".join(self.typed),"170","187",",".join(self.key)])
        ident,row=adapter.decode_output(line,{"encoded":"unit"})
        self.assertEqual(ident,"encoded");self.assertEqual(row,self.row)
        with self.assertRaises(ValueError):adapter.decode_output("OIP-MIRROR\tencoded\t0\t1\t170",{"encoded":"unit"})
    def test_model_missing_summary_and_pending_fail(self):
        for status,summary in [("0","0"),("~1","0")]:
            line="\t".join(["OIP-MIRROR","encoded",status,"1","170",summary,"","","",""])
            with self.subTest(status=status),self.assertRaises(ValueError):adapter.decode_output(line,{"encoded":"unit"})
    def test_output_cannot_enter_response_input(self):
        row={"id":"unit","mode":0,"reply_values":["0","1"],"retained_present":False,"retained_values":[]}
        response.encode_inputs([row])
        for field in ["number","source_outcome","source_afterstate","expected"]:
            poisoned=deepcopy(row);poisoned[field]=12
            with self.subTest(field=field),self.assertRaises(ValueError):response.encode_inputs([poisoned])
    def test_result_driver_identity_and_complete_rows(self):
        identity=response.IDENTITY+["0"*64]
        header="\t".join(["OIP-RESPONSE-MODEL"]+identity)
        inputs=[{"id":"unit"}];source=[{"id":"unit","number":12,"commit":2}]
        self.assertEqual(response.compare_results([header,"OIP-RESPONSE-RESULT\tunit\t12\t1\t2"],identity,inputs,source),[])
        changed=response.compare_results([header,"OIP-RESPONSE-RESULT\tunit\t50\t0\t0"],identity,inputs,source)
        self.assertEqual(len(changed),1)
        with self.assertRaises(ValueError):response.compare_results(["old identity","OIP-RESPONSE-RESULT\tunit\t12\t1\t2"],identity,inputs,source)
    def test_default_lock_is_unbound(self):
        lock=json.loads((ROOT/"tests/wire-response-artifact.lock.json").read_text(encoding="utf-8"));lock["binding_status"]="unbound"
        with patch.object(response.Path,"read_text",return_value=json.dumps(lock)),self.assertRaisesRegex(ValueError,"unbound"):
            response.read_response_lock(ROOT/"tests/wire-response-artifact.lock.json","0"*64)

if __name__=="__main__":unittest.main()
