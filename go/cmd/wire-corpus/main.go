package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/Oraclizer/oip-spec/go/wire"
	"github.com/Oraclizer/oip-spec/go/wirepb"
	"google.golang.org/protobuf/proto"
)

var uuid = []byte{0, 1, 2, 3, 4, 5, 64, 7, 128, 9, 10, 11, 12, 13, 14, 15}
var seed = slices.Repeat([]byte{7}, 32)

func header(target, family uint64, tag byte) *wirepb.Core {
	id := slices.Clone(uuid)
	id[0] = tag
	return &wirepb.Core{
		Version: proto.Uint64(6), Purpose: proto.Uint64(1), Deployment: proto.Uint64(7),
		SourceDomain: proto.Uint64(0), TargetDomain: proto.Uint64(target), Principal: proto.Uint64(7),
		KeyId: proto.Uint64(9), AuthorityEpoch: proto.Uint64(9), IssuedSeconds: proto.Uint64(100),
		TtlSeconds: proto.Uint64(5), Uuid: id, Family: proto.Uint64(family), Primary: proto.Uint64(1),
		Secondary: proto.Uint64(77), SignatureScheme: proto.Uint64(1), Atomicity: proto.Uint64(3),
		Priority: proto.Uint64(3), RouteScope: proto.Uint64(1),
	}
}
func sign(core *wirepb.Core) []byte {
	bytes, err := wire.EncodeCore(core)
	if err != nil {
		panic(err)
	}
	preimage, err := wire.SigningBytes(bytes)
	if err != nil {
		panic(err)
	}
	signature := ed25519.Sign(ed25519.NewKeyFromSeed(seed), preimage)
	packet, err := wire.EncodePacket(&wirepb.Packet{Core: core, Signature: signature})
	if err != nil {
		panic(err)
	}
	return packet
}
func legacy(family, opcode uint64, tag byte, words []uint64) []byte {
	id := slices.Clone(uuid)
	id[0] = tag
	core := wire.LegacyCore{Version: 5, Deployment: 7, Source: 0, Target: 2, Principal: 7, Key: 9, Epoch: 9,
		Sent: 100, TTL: 5, UUID: hex.EncodeToString(id), Family: family, Opcode: opcode, Words: words, Atomicity: 3, Scope: 1}
	preimage, err := core.SigningBytes()
	if err != nil {
		panic(err)
	}
	packet, err := json.Marshal(wire.LegacyPacket{Core: core, Signature: hex.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed), preimage))})
	if err != nil {
		panic(err)
	}
	return packet
}
func main() {
	query := header(2, 4, 0)
	query.Body = &wirepb.Core_Query{Query: &wirepb.Operation{Opcode: proto.Uint64(1), Words: []uint64{1, 0, 1, 17}}}
	debit := header(0, 1, 2)
	amount := make([]byte, 32)
	amount[31] = 5
	debit.Body = &wirepb.Core_StateSync{StateSync: &wirepb.Operation{
		Opcode: proto.Uint64(1), Words: []uint64{33, 33, 2, 2, 9, 0, 17, 17, 7, 2, 3, 1, 17, 0, 17, 7, 0, 9, 1, 17, 0, 0},
		Blobs: [][]byte{amount},
	}}
	receipt := header(0, 4, 3)
	original, err := wire.EncodeCore(debit)
	if err != nil {
		panic(err)
	}
	receipt.Body = &wirepb.Core_Query{Query: &wirepb.Operation{Opcode: proto.Uint64(8), Words: []uint64{2}, Blobs: [][]byte{original}}}
	fmt.Printf("query=%x\ndebit=%x\nreceipt=%x\nlegacy_query=%x\nlegacy_heartbeat=%x\n",
		sign(query), sign(debit), sign(receipt), legacy(4, 1, 5, []uint64{1, 0, 1, 17}), legacy(6, 2, 7, []uint64{3, 190}))
}
