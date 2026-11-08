val _ = use (case OS.Process.getEnv "OIP_FINITE_MODEL" of
  SOME path => path | NONE => raise Fail "OIP_FINITE_MODEL must name the hash-checked export");

fun financial_identity_text bytes = String.implode (map (fn value =>
  if value < 0 orelse value > 127 then raise Fail "Non-ASCII financial identity"
  else Char.chr (IntInf.toInt value)) bytes);

val _ = let
  val identity = map financial_identity_text (OIP_Finite_Financial.code_finite_model_identity ());
  val _ = if List.length identity = 6 then () else raise Fail "Wrong financial identity shape";
in TextIO.output (TextIO.stdOut, String.concatWith "\t" ("OIP-FINANCIAL-MODEL" :: identity) ^ "\n");
   TextIO.flushOut TextIO.stdOut end;

fun financial_integer text = case IntInf.fromString text of
  SOME value => value | NONE => raise Fail "Invalid finite input integer";
fun financial_integers "" = []
  | financial_integers text = map financial_integer (String.fields (fn c => c = #",") text);
fun financial_clean text = String.implode (List.filter (fn c => c <> #"\r" andalso c <> #"\n") (String.explode text));
fun financial_emit ident kind values =
  (TextIO.output (TextIO.stdOut, String.concatWith "\t" ["OIP-FINITE", ident, kind,
    String.concatWith "," (map IntInf.toString values)] ^ "\n"); TextIO.flushOut TextIO.stdOut);
fun financial_loop state = case TextIO.inputLine TextIO.stdIn of
  NONE => ()
| SOME line => (case String.fields (fn c => c = #"\t") (financial_clean line) of
    [ident, "seed", metadata, actors] =>
      (case OIP_Finite_Financial.code_finite_single_asset_seed (financial_integers metadata) (financial_integers actors) of
        NONE => raise Fail "Model rejected finite seed"
      | SOME runner => (financial_emit ident "SEED" (OIP_Finite_Financial.code_finite_runner_integer_view runner);
                        financial_loop (SOME runner)))
  | [ident, "step", packet, ""] => (case state of
      NONE => raise Fail "Step before finite seed"
    | SOME runner => let val (after, values) = OIP_Finite_Financial.code_finite_raw_integer_step (financial_integers packet) runner
                     in financial_emit ident "STEP" values; financial_loop (SOME after) end)
  | _ => raise Fail "Wrong finite input protocol shape");
val _ = financial_loop NONE;
