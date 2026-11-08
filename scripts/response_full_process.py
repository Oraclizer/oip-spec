"""Pinned persistent SML RPC and independently executed primitive provider."""
from pathlib import Path
import json
import queue
import subprocess
import threading
from model_diagnostics import load_allowlist,split_exact
from response_full import MetadataError,matrix_encode,matrix_decode,scalar_encode,parse_signed,byte_list

class LineProcess:
    def __init__(self,argv,cwd,env,out):
        self.out=Path(out);self.out.mkdir(parents=True,exist_ok=False)
        self.stdout=(self.out/"raw-stdout.log").open("wb");self.stderr=(self.out/"raw-stderr.log").open("wb")
        self.inputs=(self.out/"raw-stdin.log").open("wb");self.lines=queue.Queue()
        self.process=subprocess.Popen(argv,cwd=cwd,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.stderr)
        def read():
            try:
                while True:
                    line=self.process.stdout.readline(16*1024*1024+1)
                    if not line:break
                    self.stdout.write(line);self.stdout.flush()
                    self.lines.put(line)
            finally:self.lines.put(None)
        self.thread=threading.Thread(target=read,daemon=True);self.thread.start()
        (self.out/"started.json").write_text(json.dumps({"argv":list(map(str,argv)),"cwd":str(cwd),"pid":self.process.pid},indent=2)+"\n",encoding="utf-8")
    def line(self):
        try:line=self.lines.get(timeout=300)
        except queue.Empty as exc:raise MetadataError("Actual backend timed out; raw streams preserved") from exc
        if line is None:raise MetadataError("Backend terminated before its complete protocol result")
        if len(line)>16*1024*1024:raise MetadataError("Backend protocol record exceeds bound")
        return line.decode("ascii",errors="strict").rstrip("\r\n")
    def send(self,text):
        data=(text+"\n").encode("ascii");self.inputs.write(data);self.inputs.flush()
        self.process.stdin.write(data);self.process.stdin.flush()
    def close(self):
        if self.process.stdin and not self.process.stdin.closed:self.process.stdin.close()
        try:code=self.process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.process.terminate();code=self.process.wait(timeout=10)
        self.thread.join(timeout=10);self.stdout.close();self.stderr.close();self.inputs.close()
        return code

class ModelSession:
    def __init__(self,argv,root,env,out,identity,diagnostics,model_sha,driver_sha,model_path,driver_path):
        self.pipe=LineProcess(argv,root,env,out);self.identity=identity;self.counter=0
        self.allow=load_allowlist(diagnostics,model_sha,driver_sha);self.counts=[0]*len(self.allow["allowed"])
        self.model_path=model_path;self.driver_path=driver_path
        try:
            header=self._protocol()
            if header.split("\t")!=["OIP-RESPONSE-FULL-MODEL",*identity]:raise MetadataError("Missing/mismatched independent current full model identity")
        except BaseException:
            self.pipe.close();raise
    def _protocol(self):
        while True:
            line=self.pipe.line()
            if line.startswith(("OIP-RESPONSE-FULL-MODEL\t","OIP-FULL\t")):return line
            matches=[]
            for index,block in enumerate(self.allow["allowed"]):
                exact=[value.replace("{model_path}",self.model_path).replace("{driver_path}",self.driver_path) for value in block["lines"]]
                if block["stream"]=="stdout" and exact[0]==line:matches.append((index,exact))
            if len(matches)!=1:raise MetadataError("Unknown actual model output line: "+repr(line))
            index,exact=matches[0];self.counts[index]+=1
            if self.counts[index]>self.allow["allowed"][index]["maximum"]:raise MetadataError("Model diagnostic occurrence exceeded")
            if [line]+[self.pipe.line() for _ in exact[1:]]!=exact:raise MetadataError("Changed model compiler diagnostic block")
    def rpc(self,command,fields):
        ident="rpc-"+str(self.counter);self.counter+=1
        self.pipe.send("\t".join([command,ident,*fields]));line=self._protocol();parts=line.split("\t")
        if len(parts)!=5 or parts[:3]!=["OIP-FULL",ident,command]:raise MetadataError("Unknown/duplicate/out-of-order full model record")
        return parse_signed(parts[3]),matrix_decode(parts[4])
    def sender(self,command,args,tables):
        h,s,v=tables
        return self.rpc(command,[matrix_encode(args["context"]),str(args["mode"]),scalar_encode(args["reply"]),"1" if args["retained_present"] else "0",
            scalar_encode(args["retained"]),scalar_encode(args["original"]),matrix_encode(h),matrix_encode(s),matrix_encode(v)])
    def client(self,command,context,expected,network,verifies):
        status,rows=self.rpc(command,[matrix_encode(context),scalar_encode(expected),scalar_encode(network),matrix_encode(verifies)])
        if command=="C":
            if len(rows)!=1:raise MetadataError("Wrong typed client result wrapper")
            return status,rows[0]
        return status,rows
    def combined(self,args,tables,context,verifies):
        h,s,v=tables
        status,rows=self.rpc("A",[matrix_encode(args["context"]),str(args["mode"]),scalar_encode(args["reply"]),"1" if args["retained_present"] else "0",
            scalar_encode(args["retained"]),scalar_encode(args["original"]),matrix_encode(h),matrix_encode(s),matrix_encode(v),matrix_encode(context),matrix_encode(verifies)])
        if len(rows)<2 or len(rows[0])!=1:raise MetadataError("Wrong combined sender/client wrapper")
        return status,rows[2:],rows[0][0],rows[1]
    def close(self):
        code=self.pipe.close()
        if code:raise MetadataError("Actual full model failed/aborted; original streams preserved")
        _,receipt=split_exact((self.pipe.out/"raw-stdout.log").read_bytes(),(self.pipe.out/"raw-stderr.log").read_bytes(),
            prefixes=["OIP-RESPONSE-FULL-MODEL","OIP-FULL"],allowlist=self.allow,model_path=self.model_path,driver_path=self.driver_path)
        (self.pipe.out/"diagnostic-separation.json").write_text(json.dumps(receipt,indent=2)+"\n",encoding="utf-8")

class PrimitiveSession:
    def __init__(self,argv,root,env,out,fixture_keys):
        self.keys={tuple(byte_list(list(bytes.fromhex(key)),32)):value for key,value in fixture_keys.items()}
        self.pipe=LineProcess(argv,root,env,out);self.counter=0
    def __call__(self,kind,fields):
        ident="primitive-"+str(self.counter);self.counter+=1
        request={"schema":"oip-wire-primitive-request-v1","id":ident}
        if kind==0:request.update(primitive="sha256",preimage_hex=bytes(fields[0]).hex())
        elif kind==1:
            seed=self.keys.get(fields[0])
            if seed is None:raise MetadataError("Requested signing key is not an independently configured public fixture key")
            request.update(primitive="ed25519-sign",public_key_hex=bytes(fields[0]).hex(),preimage_hex=bytes(fields[1]).hex(),test_seed_byte=seed)
        else:request.update(primitive="ed25519-verify",public_key_hex=bytes(fields[0]).hex(),preimage_hex=bytes(fields[1]).hex(),signature_hex=bytes(fields[2]).hex())
        self.pipe.send(json.dumps(request,separators=(",",":"),sort_keys=True));reply=json.loads(self.pipe.line())
        if set(reply)!={"schema","id","request","answer"} or reply["schema"]!="oip-wire-primitive-reply-v1" or reply["id"]!=ident or reply["request"]!=request:raise MetadataError("Primitive answer is not keyed to the exact model request")
        answer=reply["answer"]
        if kind==0:
            if set(answer)!={"digest_hex"}:raise MetadataError("Wrong SHA primitive answer")
            return byte_list(list(bytes.fromhex(answer["digest_hex"])),32)
        if kind==1:
            if set(answer)!={"signature_hex"}:raise MetadataError("Missing primitive signature is not an empty answer")
            return byte_list(list(bytes.fromhex(answer["signature_hex"])),64)
        if set(answer)!={"valid"} or type(answer["valid"]) is not bool:raise MetadataError("Missing verification is not false")
        return answer["valid"]
    def close(self):
        if self.pipe.close():raise MetadataError("Independent primitive provider failed")
