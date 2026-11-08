package wire

// TypedValueIR is the canonical value view produced while DecodeOperands reads
// its checked semantic fields. It is not a copy of operation words or blobs.
import (
    "strconv"
    "github.com/Oraclizer/oip-spec/go/wirepb"
)

func valueScalar(value uint64) []uint64 { return []uint64{0,value} }
func valueNode(tag uint64, fields ...[]uint64) []uint64 {
    out:=[]uint64{tag,uint64(len(fields))}
    for _,field:=range fields { out=append(out,field...) }
    return out
}
func valueBytes(value []byte) []uint64 {
    out:=[]uint64{1,uint64(len(value))}
    for _,octet:=range value {out=append(out,uint64(octet))}
    return out
}
func valueList(values ...[]uint64) []uint64 {return valueNode(2,values...)}
func valueNone() []uint64 {return []uint64{3}}
func valueSome(value []uint64) []uint64 {return append([]uint64{4},value...)}
func valuePair(a,b uint64) []uint64 {return valueNode(90,valueScalar(a),valueScalar(b))}
func valueTriple(a,b,c uint64) []uint64 {return valueNode(91,valueScalar(a),valueScalar(b),valueScalar(c))}
func valueScalars(values []uint64) []uint64 {
    fields:=make([][]uint64,0,len(values));for _,value:=range values {fields=append(fields,valueScalar(value))};return valueList(fields...)
}
func valueNative(n *Native, epoch uint64) []uint64 {
    b:=n.Binding
    return valueNode(100,valueScalar(n.Reference),valuePair(n.Namespace,n.Sequence),valueScalar(n.Session),valuePair(epoch,n.Revision),
        valueScalar(n.OriginEpoch),valuePair(b.Origin.Domain,b.Origin.Event),valueScalar(b.Asset),valueScalar(b.Owner),
        valueScalar(b.Destination),valueScalar(b.Recipient),valueScalar(b.Amount),valueScalar(n.Endpoint),valueScalar(n.Caller))
}
func valueCredential(value *Credential) []uint64 {
    if value==nil {return valueNone()}
    return valueSome(valueNode(101,valueScalar(value.Asset),valueScalar(value.Holder),valueScalar(value.Generation),valueScalar(value.Epoch),valuePair(value.Origin.Domain,value.Origin.Event)))
}
func valueVersions(values [][2]uint64) []uint64 {
    fields:=make([][]uint64,0,len(values));for _,value:=range values {fields=append(fields,valuePair(value[0],value[1]))};return valueList(fields...)
}
func valueProofs(values [][]byte) []uint64 {
    fields:=make([][]uint64,0,len(values));for _,value:=range values {fields=append(fields,valueBytes(value))};return valueList(fields...)
}
func valueDeadline(op *wirepb.Operation) []uint64 {
    if value,ok:=op.AppealDeadline.(*wirepb.Operation_AppealDeadlineUtcSeconds);ok {return valueSome(valueScalar(value.AppealDeadlineUtcSeconds))}
    return valueNone()
}
func (w *words) valueSet() ([]uint64,error) {
    count,err:=w.word();if err!=nil {return nil,err}
    values,err:=w.take(count);if err!=nil || !strictlySorted(values) {return nil,ErrFormat}
    return values,nil
}
func (w *words) valueOptional(count uint64) ([]uint64,error) {
    present,err:=w.present();if err!=nil {return nil,err};if !present {return valueNone(),nil}
    values,err:=w.take(count);if err!=nil {return nil,err}
    switch count {case 1:return valueSome(valueScalar(values[0])),nil;case 2:return valueSome(valuePair(values[0],values[1])),nil;default:panic("unsupported semantic optional field")}
}
func valueQuery(values []uint64) []uint64 {
    // Called only in the actual decoder branch after validQuery succeeded.
    switch values[0] {
    case 1:return valueNode(160,valueScalar(values[1]))
    case 2:return valueNode(161,valuePair(values[1],values[2]))
    case 3:return valueNode(162,valueTriple(values[1],values[2],values[3]))
    case 4:return valueNode(163,valuePair(values[1],values[2]),valueTriple(values[3],values[4],values[5]))
    case 5:return valueNode(164,valueScalar(values[1]),valueScalar(values[2]))
    case 6:return valueNode(165,valuePair(values[1],values[2]))
    default:panic("validated query has no typed value")
    }
}
func valueCommand(family,opcode uint64,tail []uint64) []uint64 {
    switch {
    case family==1 && opcode==1:return valueNode(112,valueScalar(tail[0]))
    case family==1 && opcode==2:return valueNode(117,valueScalar(tail[0]),valueScalar(tail[1]))
    case family==1 && opcode==3:return valueNode(118,valueScalar(tail[0]))
    case family==1 && opcode==4:return valueNode(119,valueScalar(tail[0]),valueScalar(tail[1]))
    case family==1 && opcode==5:return valueNode(122)
    case family==3 && opcode==1:return valueNode(110,valueScalar(tail[0]))
    case family==3 && opcode==2:return valueNode(111,valueScalar(tail[0]))
    case family==3 && opcode==3:return valueNode(113,valueScalar(tail[0]))
    case family==3 && opcode==4:return valueNode(114,valueScalar(tail[0]))
    case family==3 && opcode==5:return valueNode(115,valueScalar(tail[0]))
    case family==3 && opcode==6:return valueNode(120,valueScalar(tail[0]),valueScalar(tail[1]))
    case family==3 && opcode==7:return valueNode(121,valueScalar(tail[0]),valueScalar(tail[1]))
    case family==3 && opcode==8:return valueNode(116,valueScalar(tail[0]))
    default:panic("validated command has no typed value")
    }
}
func TypedIRDecimal(values []uint64) []string {
    if len(values)==0 {panic("accepted decoded operand is missing its typed value")}
    out:=make([]string,len(values));for i,value:=range values {out[i]=strconv.FormatUint(value,10)};return out
}
func TransportKeyIR(key TransportKey) []uint64 {
    return valueNode(200,valueScalar(key.Deployment),valueScalar(key.Source),valueScalar(key.Principal),valueBytes(key.UUID[:]))
}
