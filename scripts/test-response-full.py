"""Pure full-ABI/broker contracts; fake RPC is never actual model evidence."""
from copy import deepcopy
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from response_full import *
from response_full_artifact import read_lock

def example(kind="boundary"):
    config={"profile":{"deployment":7,"format":1,"authority_profile":99},"endpoint":0,"other_endpoints":[2],
        "local_principal":42,"local_key_id":3,"authority_epoch":9,"route_scope":1,"response_ttl_seconds":30,"max_nesting":4,
        "response_key":[6]*32,"peers":{"7":{"identity":{"domain":0},"public_key":[7]*32},"8":{"identity":{"domain":0},"public_key":[10]*32}}}
    channel={"version":6,"deployment":7,"local":0,"remote":0,"expires":200,"families":[1,2,3,4,5,6,7],"atomicities":[1,2,3],"schemes":[1],
        "local_public_key_hex":"06"*32,"remote_public_key_hex":"07"*32}
    row={"id":"software-unit","mode":0,"reply_values":["0","1"],"retained_present":False,"retained_values":[],"raw_original_packet_hex":"aa",
        "config":config,"channel":channel,"policy_binding_hex":"bb"*32,"parameters_clock":105,"signing_clock":106,"frame_limit":1048576}
    if kind=="full":row["site"]={"profile":config["profile"],"ordered_control_present":True,"security_ordered_profile":config["profile"]}
    return row

class BrokerContracts(unittest.TestCase):
    def test_matrix_roundtrip_preserves_empty_and_signed_rows(self):
        for rows in [[],[[]],[[1,2],[],[3]],[[0],[-3],[]]]:self.assertEqual(matrix_decode(matrix_encode(rows)),rows)
    def test_matrix_rejects_truncated_trailing_and_noncanonical(self):
        for text in ["","1","1,3,1","0,1","01", "~1"]:
            with self.subTest(text=text),self.assertRaises(MetadataError):matrix_decode(text)
    def test_principal_keyed_same_domain_peers_not_collapsed(self):
        data=sender_input(example(),"boundary")["context"]
        self.assertEqual(data[8],[0,0]);self.assertEqual(data[14], [7]*32);self.assertEqual(data[15],[10]*32)
        self.assertEqual(data[6][1:3],[42,3]);self.assertEqual(data[12],[1,105,1,106])
    def test_absent_mode_is_full_only_and_never_dummy(self):
        row=example("full");row.update(mode=3,reply_values=[],retained_present=False,retained_values=[])
        self.assertEqual(sender_input(row,"full")["mode"],3)
        with self.assertRaises(MetadataError):sender_input(row,"boundary")
        row["reply_values"]=["0"]
        with self.assertRaises(MetadataError):sender_input(row,"full")
    def test_full_requires_actual_site_but_boundary_does_not_fabricate_it(self):
        with self.assertRaises(MetadataError):sender_input(example(),"full")
        self.assertEqual(sender_input(example(),"boundary")["context"][11],[0]*8)
    def test_source_answers_are_not_sender_inputs(self):
        for key in ["source_afterstate","response_packet_hex","binding_digest_hex","uuid_hex","signature_hex","expected","source_result_number"]:
            row=example();row[key]="poisoned"
            with self.subTest(key=key),self.assertRaises(MetadataError):sender_input(row,"boundary")
    def test_clock_none_and_independent_values(self):
        row=example();row["parameters_clock"]=None
        self.assertEqual(sender_input(row,"boundary")["context"][12],[0,0,1,106])
    def test_request_is_exact_length_prefixed(self):
        kind,fields=decode_request([1,32,*([6]*32),2,1,2]);self.assertEqual((kind,fields),(1,(tuple([6]*32),(1,2))))
        for row in [[0],[0,2,1],[2,31,*([1]*31),0,0],[9,0],[0,0,1]]:
            with self.subTest(row=row),self.assertRaises(MetadataError):decode_request(row)
    def test_false_verification_is_present_and_not_missing(self):
        record=[2,32,*([7]*32),1,99,1,1];t=Transcript();t.fill(record,lambda *_:False)
        self.assertEqual(t.rows()[2][-1],[0])
        with self.assertRaises(MetadataError):t.fill(record,lambda *_:False)
    def test_missing_answers_never_become_empty_signature_or_false(self):
        for request,answer in [([0,0],[]),([1,32,*([6]*32),0],[]),([2,32,*([7]*32),0,0],None)]:
            with self.subTest(request=request),self.assertRaises((MetadataError,TypeError)):Transcript().fill(request,lambda *_:answer)
    def test_broker_converges_only_from_model_request(self):
        class FakeRPC:
            def sender(self,command,args,tables):
                if command in {"Q","q"}:return (0,[[0,1,42]]) if not tables[0] else (0,[])
                if command in {"P","p"}:return 0,[[] for _ in range(14)]
                return 70,[]
        calls=[]
        def provider(kind,fields):calls.append((kind,fields));return [11]*32
        result=complete_sender(FakeRPC(),example(),"boundary",provider)
        self.assertEqual(result["status"],70);self.assertEqual(calls,[(0,((42,),))])
    def test_stalled_planner_and_negative_metadata_abort(self):
        class Stalled:
            def sender(self,*_):return 0,[[0,0]]
        with self.assertRaises(MetadataError):complete_sender(Stalled(),example(),"boundary",lambda *_:[1]*32)
        class Missing:
            def sender(self,*_):return -2,[]
        with self.assertRaises(MetadataError):complete_sender(Missing(),example(),"boundary",lambda *_:False)
    def test_malformed_success_cannot_pass_as_an_accept_bit(self):
        class EmptySuccess:
            def sender(self,command,*_):
                if command in {"Q","q"}:return 0,[]
                return 0,[]
        with self.assertRaises(MetadataError):complete_sender(EmptySuccess(),example(),"boundary",lambda *_:False)
    def test_client_keeps_typed_unknown(self):
        class Unknown:
            def client(self,command,*_):return (0,[]) if command=="V" else (0,[7,33,3,999,0,0,0,3,999])
        result=complete_client(Unknown(),[],[],[],lambda *_:False)
        self.assertEqual(result["result"][-3:],[0,3,999])
    def test_unbound_full_lock_cannot_accept_old_model(self):
        path=Path(__file__).resolve().parent.parent/"tests/wire-response-artifact.lock.json"
        lock=json.loads(path.read_text(encoding="utf-8"));lock["binding_status"]="unbound"
        with patch.object(Path,"read_text",return_value=json.dumps(lock)),self.assertRaisesRegex(ValueError,"unbound"):read_lock(path)
    def test_full_identity_function_is_cross_checked_with_entry(self):
        path=Path(__file__).resolve().parent.parent/"tests/wire-response-artifact.lock.json"
        lock=json.loads(path.read_text(encoding="utf-8"));lock.update(binding_status="bound",identity_function="OIP_Wire_Response_Boundary.code_response_result_model_identity")
        with patch.object(Path,"read_text",return_value=json.dumps(lock)),self.assertRaisesRegex(ValueError,"coidentity"):read_lock(path)
    def test_old_result_abi_cannot_approve_full(self):
        path=Path(__file__).resolve().parent.parent/"tests/wire-response-artifact.lock.json"
        lock=json.loads(path.read_text(encoding="utf-8"));lock.update(binding_status="bound",abi="intinf-response-result-v1")
        with patch.object(Path,"read_text",return_value=json.dumps(lock)),self.assertRaisesRegex(ValueError,"identity"):read_lock(path)

if __name__=="__main__":unittest.main()
