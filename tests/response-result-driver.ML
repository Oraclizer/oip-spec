val _ = use (case OS.Process.getEnv "OIP_WIRE_RESPONSE_MODEL" of SOME path => path
  | NONE => raise Fail "OIP_WIRE_RESPONSE_MODEL must name the pinned model");
fun response_integer text = case IntInf.fromString text of SOME value => value | NONE => raise Fail "Invalid response-boundary integer";
fun response_integers "" = [] | response_integers text = map response_integer (String.fields (fn c => c = #",") text);
fun response_bool "0" = false | response_bool "1" = true | response_bool _ = raise Fail "Bad retained presence";
fun response_clean text = String.implode (List.filter (fn c => c <> #"\r" andalso c <> #"\n") (String.explode text));
fun response_identity_text bytes = String.implode (map (fn value =>
  if value < 0 orelse value > 127 then raise Fail "Non-ASCII response identity" else Char.chr (IntInf.toInt value)) bytes);
fun response_line line = case String.fields (fn c => c = #"\t") (response_clean line) of
  [id,mode,reply,present,retained] => let
    val (ok,(number,(commit_present,position)))=OIP_Wire_Response_Boundary.code_response_result_flat_oracle
      (response_integer mode) (response_integers reply) (response_bool present) (response_integers retained);
    val _ = if ok then () else raise Fail "Incomplete response-boundary metadata";
  in TextIO.output (TextIO.stdOut,String.concatWith "\t" ["OIP-RESPONSE-RESULT",id,IntInf.toString number,
       if commit_present then "1" else "0",IntInf.toString position] ^ "\n");TextIO.flushOut TextIO.stdOut end
| _ => raise Fail "Wrong response input field count";
fun response_loop () = case TextIO.inputLine TextIO.stdIn of NONE => () | SOME line => (response_line line;response_loop ());
val _ = let val fields=map response_identity_text (OIP_Wire_Response_Boundary.code_response_full_model_identity ());
            val _ = if List.length fields=6 then () else raise Fail "Wrong response model identity shape";
        in TextIO.output (TextIO.stdOut,String.concatWith "\t" ("OIP-RESPONSE-MODEL"::fields)^"\n");
           TextIO.flushOut TextIO.stdOut;response_loop () end;
