package wire

import (
	"bytes"
	"encoding/json"
	"slices"

	"github.com/Oraclizer/oip-spec/go/wirepb"
)

type Origin struct{ Domain, Event uint64 }
type Binding struct {
	Origin                                       Origin
	Asset, Owner, Destination, Recipient, Amount uint64
}
type Credential struct {
	Asset                     uint64
	Origin                    Origin
	Holder, Generation, Epoch uint64
}
type Native struct {
	Namespace, Endpoint, Caller uint64
	Summary []uint64
	Reference, Sequence, Session, Revision, OriginEpoch uint64
	Binding                                             Binding
	Credential                                          *Credential
	Versions                                            [][2]uint64
}
type Operands struct {
	TypedIR []uint64
	Family, Opcode, Session uint64
	Native                  *Native
	Sync                    *SyncCommitment
	CommitmentQuery         *CurrentCommitment
	Words                   []uint64
	Blobs                   [][]byte
	Original                *wirepb.Core
}

// words reads operand words in order. A read past the last word fails with
// ErrFormat, and each decoder returns its first failure, so a frame with
// several defects receives the same error as from the reference decoder.
type words struct{ items []uint64 }

func (w *words) word() (uint64, error) {
	if len(w.items) == 0 {
		return 0, ErrFormat
	}
	value := w.items[0]
	w.items = w.items[1:]
	return value, nil
}
func (w *words) read(targets ...*uint64) error {
	for _, target := range targets {
		value, err := w.word()
		if err != nil {
			return err
		}
		*target = value
	}
	return nil
}
func (w *words) take(count uint64) ([]uint64, error) {
	if count > uint64(len(w.items)) {
		return nil, ErrFormat
	}
	result := w.items[:count]
	w.items = w.items[count:]
	return result, nil
}
func (w *words) present() (bool, error) {
	value, err := w.word()
	if err != nil || value > 1 {
		return false, ErrFormat
	}
	return value == 1, nil
}
func (w *words) set() error {
	count, err := w.word()
	if err != nil {
		return err
	}
	values, err := w.take(count)
	if err != nil || !strictlySorted(values) {
		return ErrFormat
	}
	return nil
}
func (w *words) optional(count uint64) error {
	present, err := w.present()
	if err == nil && present {
		_, err = w.take(count)
	}
	return err
}
func (w *words) end() error {
	if len(w.items) != 0 {
		return ErrFormat
	}
	return nil
}

func validQuery(values []uint64) bool {
	if len(values) == 0 {
		return false
	}
	sizes := [...]int{0, 2, 3, 4, 6, 3, 3}
	return values[0] < uint64(len(sizes)) && sizes[values[0]] == len(values)
}

func decodeRead(op *wirepb.Operation, depth int, epoch uint64, summary *[]uint64) (uint64, *wirepb.Core, error) {
    w:=words{items:op.Words}
    session,err:=w.word()
    if err!=nil || op.AppealDeadline!=nil {return 0,nil,ErrFormat}
    if op.GetOpcode()==8 {
        if w.end()!=nil || len(op.Blobs)!=1 || depth<=1 {return 0,nil,ErrFormat}
        original,err:=DecodeCore(op.Blobs[0]);if err!=nil {return 0,nil,err}
        typed,err:=DecodeOperands(original,depth-1);if err!=nil {return 0,nil,err}
        if typed.Native==nil && typed.Sync==nil {return 0,nil,ErrFormat}
        canonical,err:=EncodeCore(original);if err!=nil {return 0,nil,err}
        *summary=valueNode(15,valueScalar(session),valueBytes(canonical),typed.TypedIR)
        return session,original,nil
    }
    if len(op.Blobs)!=0 {return 0,nil,ErrFormat}
    proof:=valueNode(104,valueScalar(session),valueScalar(epoch))
    var request []uint64
    switch op.GetOpcode() {
    case 1,2:
        revision,err:=w.word();if err!=nil || !validQuery(w.items) {return 0,nil,ErrFormat}
        if op.GetOpcode()==1 {request=valueNode(150,valueQuery(w.items),valuePair(epoch,revision))} else {request=valueNode(151,valueQuery(w.items),valueScalar(revision))}
    case 3,6:
        if !validQuery(w.items) {return 0,nil,ErrFormat}
        if op.GetOpcode()==6 {*summary=valueNode(14,proof,valueQuery(w.items));return session,nil,nil}
        request=valueNode(152,valueQuery(w.items))
    case 4:
        values,err:=w.take(2);if err!=nil || w.end()!=nil {return 0,nil,ErrFormat}
        request=valueNode(153,valuePair(values[0],values[1]))
    case 5:
        if w.end()!=nil {return 0,nil,ErrFormat};request=valueNode(154)
    case 7:
        asset,err:=w.word();if err!=nil || w.end()!=nil {return 0,nil,ErrFormat};request=valueNode(155,valueScalar(asset))
    default:return 0,nil,ErrFormat
    }
    *summary=valueNode(13,proof,request)
    return session,nil,nil
}

func amount(raw []byte) (uint64, error) {
	amount, err := DecodeAmount(raw)
	if err != nil {
		return 0, err
	}
	return amount.ProductAmount()
}
func kind(value uint64) bool { return value == 1 || value == 2 }

// native reads the call prefix that ordinary, legal and spend operations
// share: the words in order, then the amount in the first blob.
func native(core *wirepb.Core, op *wirepb.Operation) (*Native, words, error) {
	w := words{items: op.Words}
	n := &Native{Namespace:core.GetPrincipal(),Endpoint:core.GetTargetDomain(),Caller:core.GetPrincipal()}
	b := &n.Binding
	if err := w.read(&n.Reference, &n.Sequence, &n.Session, &n.Revision, &n.OriginEpoch,
		&b.Origin.Domain, &b.Origin.Event, &b.Asset, &b.Owner, &b.Destination, &b.Recipient); err != nil {
		return nil, w, err
	}
	if len(op.Blobs) == 0 {
		return nil, w, ErrFormat
	}
	value, err := amount(op.Blobs[0])
	if err != nil {
		return nil, w, err
	}
	b.Amount = value
	return n, w, nil
}

func ordinary(core *wirepb.Core, family uint64, op *wirepb.Operation) (*Native, error) {
	if op.AppealDeadline != nil {
		return nil, ErrFormat
	}
	n, w, err := native(core,op)
	if err != nil {
		return nil, err
	}
	credential, err := w.present()
	if err != nil {
		return nil, err
	}
	if credential {
		c := &Credential{}
		if err := w.read(&c.Asset, &c.Origin.Domain, &c.Origin.Event, &c.Holder, &c.Generation, &c.Epoch); err != nil {
			return nil, err
		}
		n.Credential = c
	}
	count, err := w.word()
	if err != nil || count > uint64(len(w.items))/2 {
		return nil, ErrFormat
	}
	values, _ := w.take(2 * count)
	for i := 0; i < len(values); i += 2 {
		if i != 0 && values[i-2] >= values[i] {
			return nil, ErrFormat
		}
		n.Versions = append(n.Versions, [2]uint64{values[i], values[i+1]})
	}
	// The command words, the proofs that the command carries and the endpoint
	// that it names. The words are checked before the endpoint, and the
	// proofs after it.
	expected, proofs, target := 1, 0, n.Binding.Origin.Domain
	if family == 1 {
		switch op.GetOpcode() {
		case 1:
		case 2, 4:
			expected, proofs = 2, 1
		case 3:
			target = n.Binding.Destination
		case 5:
			expected = 0
		default:
			return nil, ErrFormat
		}
	} else {
		switch op.GetOpcode() {
		case 1, 2, 8:
		case 3, 4, 5:
			proofs = 1
		case 6:
			expected, proofs = 2, 1
		case 7:
			expected = 2
		default:
			return nil, ErrFormat
		}
	}
	if len(w.items) != expected || (family == 1 && op.GetOpcode() == 2 && !kind(w.items[0])) {
		return nil, ErrFormat
	}
	if target != core.GetTargetDomain() {
		return nil, ErrSource
	}
	if len(op.Blobs) != 1+proofs || (proofs == 1 && len(op.Blobs[1]) == 0) {
		return nil, ErrFormat
	}
	n.Summary=valueNode(10,valueNative(n,core.GetAuthorityEpoch()),valueCredential(n.Credential),valueVersions(n.Versions),valueCommand(family,op.GetOpcode(),w.items),valueProofs(op.Blobs[1:]))
	return n, nil
}

func legal(core *wirepb.Core, op *wirepb.Operation) (*Native,error) {
    n,w,err:=native(core,op);if err!=nil {return nil,err}
    opcode:=op.GetOpcode()
    if len(op.Blobs)!=2 || len(op.Blobs[1])==0 || (opcode!=1 && opcode!=2) {return nil,ErrFormat}
    var action,issuance,officer,jurisdiction,basis uint64
    if err:=w.read(&action);err!=nil || action<1 || action>7 {return nil,ErrFormat}
    if err:=w.read(&officer,&jurisdiction,&basis);err!=nil {return nil,err}
    if err:=w.read(&issuance);err!=nil {return nil,err}
    scope,err:=w.valueSet();if err!=nil {return nil,err}
    predecessor,err:=w.valueOptional(2);if err!=nil {return nil,err}
    destination,err:=w.valueOptional(1);if err!=nil {return nil,err}
    if err:=w.end();err!=nil {return nil,err}
    target:=n.Binding.Origin.Domain;if opcode==2 {target=n.Binding.Destination}
    if target!=core.GetTargetDomain() || issuance!=n.OriginEpoch {return nil,ErrSource}
    fields:=valueNode(102,valueScalar(action),valueScalar(officer),valueScalar(jurisdiction),valueScalar(basis),valueScalar(issuance),valueScalars(scope),predecessor,destination,valueDeadline(op))
    n.Summary=valueNode(11,valueNative(n,core.GetAuthorityEpoch()),valueScalar(opcode-1),fields,valueBytes(op.Blobs[1]))
    return n,nil
}

func spend(core *wirepb.Core, family uint64, op *wirepb.Operation) (*Native,error) {
    n,w,err:=native(core,op);if err!=nil {return nil,err}
    var reference,sender,recipient uint64
    if err:=w.read(&reference,&sender,&recipient);err!=nil {return nil,err}
    var kind uint64
    if err:=w.read(&kind);err!=nil || (family==1 && kind!=0) || (family==2 && (kind<1 || kind>4)) {return nil,ErrFormat}
    if len(op.Blobs)<2 {return nil,ErrFormat}
    fullAmount,err:=amount(op.Blobs[1]);if err!=nil {return nil,err}
    authorization,proof:=valueNone(),valueNone()
    if family==2 {
        if len(op.Blobs)!=3 || len(op.Blobs[2])==0 {return nil,ErrFormat}
        var officer,jurisdiction,basis uint64
        if err:=w.read(&officer,&jurisdiction,&basis);err!=nil {return nil,err}
        assets,err:=w.valueSet();if err!=nil {return nil,err}
        prior,err:=w.valueOptional(2);if err!=nil {return nil,err}
        authorization=valueSome(valueNode(108,valueScalar(officer),valueScalar(jurisdiction),valueScalar(basis),valueScalars(assets),prior,valueDeadline(op)))
        proof=valueSome(valueBytes(op.Blobs[2]))
    } else if len(op.Blobs)!=2 || op.AppealDeadline!=nil {return nil,ErrFormat}
    if err:=w.end();err!=nil {return nil,err}
    if core.GetTargetDomain()!=n.Binding.Destination {return nil,ErrSource}
    n.Summary=valueNode(12,valueNative(n,core.GetAuthorityEpoch()),valueNode(103,valueScalar(reference),valueScalar(sender),valueScalar(recipient),valueScalar(kind),valueScalar(fullAmount),authorization,proof))
    return n,nil
}

// sameOriginal is unchanged: matching receipt deployment/domains/principal/epoch.
func sameOriginal(core, original *wirepb.Core) bool {
    return core.GetDeployment()==original.GetDeployment() && core.GetSourceDomain()==original.GetSourceDomain() &&
        core.GetTargetDomain()==original.GetTargetDomain() && core.GetPrincipal()==original.GetPrincipal() &&
        core.GetAuthorityEpoch()==original.GetAuthorityEpoch() && original.GetVersion()==6
}

// responseStatus checks the kind and commit presence at the operand boundary.
func responseStatus(kind, code uint64, committed, syncCall bool) error {
	if kind < 1 || kind > 3 || (kind != 1 && committed) {
		return ErrFormat
	}
	if syncCall {
		switch code {
		case 29, 39, 40, 41:
			if kind != 1 || committed != (code == 29) {
				return ErrFormat
			}
		}
	}
	return nil
}

// syncResponseStatus checks the existing code assignments that can apply to
// a synchronization call. The other recorded assignments belong to earlier
// calls. An unknown code keeps its raw value and the kind's commit rules.
func syncResponseStatus(kind, code uint64, committed bool) error {
	switch {
	case code >= 1 && code <= 3:
		if kind == 1 && !committed {
			return nil
		}
	case code == 4 || (code >= 10 && code <= 28) || (code >= 30 && code <= 38):
		return ErrFormat
	case code >= 50 && code <= 56:
		if kind == 2 {
			return nil
		}
	case code >= 70 && code <= 77:
		if kind == 3 {
			return nil
		}
	default:
		return nil
	}
	return ErrFormat
}

func response(core *wirepb.Core, op *wirepb.Operation, depth int, summary *[]uint64) (*wirepb.Core, error) {
	if len(op.Blobs) != 1 {
		return nil, ErrFormat
	}
	original, err := DecodeCore(op.Blobs[0])
	if err != nil {
		return nil, err
	}
	if depth <= 1 {
		return nil, ErrFormat
	}
	nested, err := DecodeOperands(original, depth-1)
	if err != nil {
		return nil, err
	}
	w := words{items: op.Words}
	var namespace, sequence, kind, code, position uint64
	if err := w.read(&namespace, &sequence, &kind, &code); err != nil {
		return nil, err
	}
	committed, err := w.present()
	if err != nil {
		return nil, err
	}
	if committed {
		if err := w.read(&position); err != nil {
			return nil, err
		}
	}
	if err := w.end(); err != nil {
		return nil, err
	}
	callFamily, callOpcode := nested.Family, nested.Opcode
	isReceipt := callFamily == 4 && callOpcode == 8
	var innerOp *wirepb.Operation
	if isReceipt {
		callFamily, innerOp = Body(nested.Original)
		callOpcode = innerOp.GetOpcode()
	}
	syncCall := callFamily == 1 && callOpcode == 7
	if err := responseStatus(kind, code, committed, syncCall); err != nil {
		return nil, err
	}
	if original.GetVersion() != core.GetVersion() || original.GetDeployment() != core.GetDeployment() ||
		original.GetPrincipal() != namespace || original.GetSourceDomain() != core.GetTargetDomain() ||
		original.GetTargetDomain() != core.GetSourceDomain() {
		return nil, ErrSource
	}
	// A committed Debit response names the revision that the Debit names.
	debitAt := func(family, opcode, revision uint64) bool {
		return family != 1 || opcode != 1 || !committed || position == revision
	}
	switch {
	case nested.Family == 5 && nested.Opcode == 2:
		return nil, ErrFormat
	case nested.Native != nil:
		if nested.Native.Sequence != sequence || !debitAt(nested.Family, nested.Opcode, nested.Native.Revision) {
			return nil, ErrFormat
		}
	case nested.Sync != nil:
		if nested.Sync.Sequence != sequence {
			return nil, ErrFormat
		}
	case isReceipt:
		// A receipt request answers for the original call that it carries.
		inner := nested.Original
		if !sameOriginal(original, inner) {
			return nil, ErrSource
		}
		// Receipt decoding already validated the original as a call. All
		// receiptable calls use word 2 for sequence and word 4 for revision.
		if inner.GetPrincipal() != namespace || innerOp.Words[1] != sequence ||
			!debitAt(callFamily, callOpcode, innerOp.Words[3]) {
			return nil, ErrFormat
		}
	case nested.CommitmentQuery != nil:
		return nil, ErrFormat
	}
	if syncCall {
		if err := syncResponseStatus(kind, code, committed); err != nil {
			return nil, err
		}
	}
	canonical,err:=EncodeCore(original);if err!=nil {return nil,err}
	commit:=valueNone();if committed {commit=valueSome(valueScalar(position))}
	*summary=valueNode(16,valuePair(namespace,sequence),valueScalar(kind),valueScalar(code),commit,valueBytes(canonical),nested.TypedIR)
	return original, nil
}

func ack(core *wirepb.Core, op *wirepb.Operation, depth int, summary *[]uint64) (*wirepb.Core,error) {
    if op.AppealDeadline!=nil {return nil,ErrFormat}
    if op.GetOpcode()==2 {return response(core,op,depth,summary)}
    if len(op.Blobs)!=1 {return nil,ErrFormat}
    w:=words{items:op.Words}
    var originDomain,originEvent,commit,target,asset,owner,destination,recipient uint64
    if err:=w.read(&originDomain,&originEvent,&commit,&target,&asset,&owner,&destination,&recipient);err!=nil {return nil,err}
    fullAmount,err:=amount(op.Blobs[0]);if err!=nil {return nil,err}
    var originEpoch,status uint64
    if err:=w.read(&originEpoch,&status);err!=nil || !kind(status) {return nil,ErrFormat}
    if err:=w.end();err!=nil {return nil,err}
    *summary=valueNode(17,valueNode(105,valuePair(originDomain,originEvent),valueScalar(commit),valueScalar(target),valueScalar(asset),valueScalar(owner),valueScalar(destination),valueScalar(recipient),valueScalar(fullAmount),valueScalar(originEpoch),valueScalar(status)))
    return nil,nil
}


func heartbeat(core *wirepb.Core, op *wirepb.Operation, summary *[]uint64) error {
    if op.AppealDeadline!=nil || len(op.Blobs)!=0 {return ErrFormat}
    w:=words{items:op.Words};var challenge,expires uint64
    if err:=w.read(&challenge,&expires);err!=nil {return err}
    if op.GetOpcode()==1 {
        sets:=make([][]uint64,0,4)
        for range 4 {values,err:=w.valueSet();if err!=nil {return err};sets=append(sets,valueScalars(values))}
        if err:=w.end();err!=nil {return err}
        *summary=valueNode(18,valueScalar(core.GetDeployment()),valueScalar(core.GetSourceDomain()),valueScalar(core.GetTargetDomain()),valueScalar(challenge),valueScalar(expires),sets[0],sets[1],sets[2],sets[3])
    } else {
        if err:=w.end();err!=nil {return err}
        *summary=valueNode(19,valueScalar(challenge),valueScalar(expires))
    }
    return nil
}

type contextRecord struct {
	Endpoint         *uint64             `json:"endpoint"`
	Epoch            *uint64             `json:"epoch"`
	Grants           [][]json.RawMessage `json:"grants"`
	Dependencies     [][]json.RawMessage `json:"dependencies"`
	WritePermissions [][3]uint64         `json:"write_permissions"`
}
type sessionRecord struct {
	Principal      *uint64 `json:"principal"`
	AuthorityEpoch *uint64 `json:"authority_epoch"`
}

func canonicalJSON(raw []byte, value any) bool {
	if json.Unmarshal(raw, value) != nil {
		return false
	}
	encoded, err := json.Marshal(value)
	return err == nil && bytes.Equal(raw, encoded)
}

func tupleSorted(values [][3]uint64) bool {
	for i := 1; i < len(values); i++ {
		a, b := values[i-1], values[i]
		if a[0] > b[0] || (a[0] == b[0] && (a[1] > b[1] || (a[1] == b[1] && a[2] >= b[2]))) {
			return false
		}
	}
	return true
}

func validContexts(raw []byte, summary ...*[]uint64) bool {
	var contexts []contextRecord
	if !canonicalJSON(raw, &contexts) || len(contexts) == 0 {
		return false
	}
	routes := []string{"Normal", "Administrative", "Adapter"}
	permissions := []string{"Reserve", "Dispatch", "Debit", "Cancel", "Fence", "Preempt", "ObserveTime", "Attest",
		"Credit", "Refund", "Reconcile", "Write", "PublishPrimary"}
	var projected [][]uint64
	var priorEndpoint uint64
	for i, c := range contexts {
		if c.Endpoint == nil || c.Epoch == nil || c.Grants == nil || c.Dependencies == nil || c.WritePermissions == nil ||
			(i > 0 && priorEndpoint >= *c.Endpoint) || !tupleSorted(c.WritePermissions) {
			return false
		}
		priorEndpoint = *c.Endpoint
		var grants [][3]uint64
		for _, item := range c.Grants {
			var actor uint64
			var route, permission string
			if len(item) != 3 || !canonicalJSON(item[0], &actor) || !canonicalJSON(item[1], &route) || !canonicalJSON(item[2], &permission) {
				return false
			}
			r, p := slices.Index(routes, route), slices.Index(permissions, permission)
			if r < 0 || p < 0 {
				return false
			}
			grants = append(grants, [3]uint64{actor, uint64(r), uint64(p)})
		}
		if !tupleSorted(grants) {
			return false
		}
		var dependencyValues [][]uint64
		var prior uint64
		for j, item := range c.Dependencies {
			var asset uint64
			var dependencies []uint64
			if len(item) != 2 || !canonicalJSON(item[0], &asset) || !canonicalJSON(item[1], &dependencies) ||
				dependencies == nil || !strictlySorted(dependencies) || (j > 0 && prior >= asset) {
				return false
			}
			prior = asset
			dependencyValues=append(dependencyValues,valueNode(109,valueScalar(asset),valueScalars(dependencies)))
		}
		grantValues:=make([][]uint64,0,len(grants));for _,v:=range grants {grantValues=append(grantValues,valueTriple(v[0],v[1],v[2]))}
		writeValues:=make([][]uint64,0,len(c.WritePermissions));for _,v:=range c.WritePermissions {writeValues=append(writeValues,valueTriple(v[0],v[1],v[2]))}
		projected=append(projected,valueNode(106,valueScalar(*c.Endpoint),valueScalar(*c.Epoch),valueList(grantValues...),valueList(dependencyValues...),valueList(writeValues...)))
	}
	if len(summary)>0 {*summary[0]=valueList(projected...)}
	return true
}

func validSessions(raw []byte, summary ...*[]uint64) bool {
	var sessions [][]json.RawMessage
	if !canonicalJSON(raw, &sessions) || sessions == nil {
		return false
	}
	var projected [][]uint64
	var prior uint64
	for i, item := range sessions {
		var id uint64
		var session sessionRecord
		if len(item) != 2 || !canonicalJSON(item[0], &id) || !canonicalJSON(item[1], &session) ||
			session.Principal == nil || session.AuthorityEpoch == nil || (i > 0 && prior >= id) {
			return false
		}
		prior = id
		projected=append(projected,valueNode(107,valueScalar(id),valueScalar(*session.Principal),valueScalar(*session.AuthorityEpoch)))
	}
	if len(summary)>0 {*summary[0]=valueList(projected...)}
	return true
}

func governance(core *wirepb.Core, op *wirepb.Operation, summary *[]uint64) (uint64,error) {
    if op.AppealDeadline!=nil {return 0,ErrFormat}
    w:=words{items:op.Words};var session,revision uint64
    if err:=w.read(&session,&revision);err!=nil {return 0,err}
    var contextsIR []uint64
    if len(op.Blobs)!=3 || len(op.Blobs[1])==0 || len(op.Blobs[2])==0 || !validContexts(op.Blobs[0],&contextsIR) {return 0,ErrFormat}
    expected:=valuePair(core.GetAuthorityEpoch(),revision)
    if op.GetOpcode()==1 {
        var asset,previous,successor,oldSession,newSession,epoch uint64
        if err:=w.read(&asset,&previous,&successor,&oldSession,&newSession,&epoch);err!=nil {return 0,err}
        if err:=w.end();err!=nil {return 0,err}
        *summary=valueNode(20,valueScalar(session),expected,valueScalar(asset),valueScalar(previous),valueScalar(successor),valueScalar(oldSession),valueScalar(newSession),valueScalar(epoch),contextsIR,valueBytes(op.Blobs[1]),valueBytes(op.Blobs[2]))
    } else {
        var sessionsIR []uint64
        if !validSessions(op.Blobs[1],&sessionsIR) {return 0,ErrFormat}
        epoch,err:=w.word();if err!=nil {return 0,err}
        if err:=w.end();err!=nil {return 0,err}
        *summary=valueNode(21,valueScalar(session),expected,valueScalar(epoch),contextsIR,sessionsIR,valueBytes(op.Blobs[2]))
    }
    return session,nil
}

func DecodeOperands(core *wirepb.Core, maxNesting int) (Operands, error) {
	if maxNesting < 1 {
		return Operands{}, ErrFormat
	}
	family, op := Body(core)
	if op == nil {
		return Operands{}, ErrFormat
	}
	opcode := op.GetOpcode()
	typed := Operands{Family: family, Opcode: opcode, Words: slices.Clone(op.Words)}
	for _, blob := range op.Blobs {
		typed.Blobs = append(typed.Blobs, bytes.Clone(blob))
	}
	var err error
	switch {
	case family == 1 && opcode == 7:
		typed.Sync, typed.TypedIR, err = decodeSyncCommitment(core, op)
		if typed.Sync != nil {
			typed.Session = typed.Sync.Session
		}
	case (family == 1 && opcode == 6) || (family == 2 && opcode == 3):
		typed.Native, err = spend(core, family, op)
	case family == 1 || family == 3:
		typed.Native, err = ordinary(core, family, op)
	case family == 2:
		typed.Native, err = legal(core, op)
	case family == 4 && opcode == 9:
		typed.CommitmentQuery, typed.TypedIR, err = decodeCurrentCommitment(core, op)
		if typed.CommitmentQuery != nil {
			typed.Session = typed.CommitmentQuery.Session
		}
	case family == 4:
		typed.Session, typed.Original, err = decodeRead(op,maxNesting,core.GetAuthorityEpoch(),&typed.TypedIR)
	case family == 5:
		typed.Original, err = ack(core,op,maxNesting,&typed.TypedIR)
	case family == 6:
		err = heartbeat(core,op,&typed.TypedIR)
	case family == 7:
		typed.Session, err = governance(core,op,&typed.TypedIR)
	default:
		err = ErrFormat
	}
	if typed.Native != nil {
		typed.Session = typed.Native.Session
		typed.TypedIR = typed.Native.Summary
	}
	if err != nil {
		return Operands{}, err
	}
	return typed, nil
}

// ReferenceAccepts reports whether the reference configuration executes the
// operation of a decoded Core. The v0.6.1 configuration accepts 28 of the 33
// operations and refuses Timeout, CorrelatedResponse, Capabilities, Liveness
// and InstallEpoch.
func ReferenceAccepts(core *wirepb.Core) bool {
	family, op := Body(core)
	opcode := op.GetOpcode()
	switch family {
	case 1:
		return opcode >= 1 && opcode <= 7
	case 3:
		return opcode >= 1 && opcode <= 7
	case 2:
		return opcode >= 1 && opcode <= 3
	case 4:
		return opcode >= 1 && opcode <= 9
	case 5, 7:
		return opcode == 1
	default:
		return false
	}
}

type Arrival uint8

const (
	First Arrival = iota
	Identical
)

type TransportBindings struct{ entries map[TransportKey][]byte }

func (store *TransportBindings) Len() int { return len(store.entries) }
func (store *TransportBindings) bind(key TransportKey, exact []byte) (Arrival, error) {
	if prior, ok := store.entries[key]; ok {
		if !bytes.Equal(prior, exact) {
			return First, ErrReplay
		}
		return Identical, nil
	}
	if store.entries == nil {
		store.entries = make(map[TransportKey][]byte)
	}
	store.entries[key] = bytes.Clone(exact)
	return First, nil
}

// Receive admits a version 6 frame and binds its transport key. The attest
// callback checks the admitted Core before its operands are decoded.
func (store *TransportBindings) Receive(raw []byte, profile Profile, boundary Boundary, attest func(*wirepb.Core) bool) (Arrival, *CanonicalPacket, error) {
	return store.ReceiveAccepting(raw, profile, boundary, nil, attest)
}

// ReceiveAccepting is Receive with the operation check that a configuration
// runs in front of the admission gate. An operation that accepts refuses
// receives ErrVersion before any signature or source check. A nil accepts
// admits every operation.
func (store *TransportBindings) ReceiveAccepting(raw []byte, profile Profile, boundary Boundary,
	accepts func(*wirepb.Core) bool, attest func(*wirepb.Core) bool) (Arrival, *CanonicalPacket, error) {
	if profile.Version != 6 {
		return First, nil, ErrVersion
	}
	if err := CheckDeclaredVersion(raw, boundary.MaxFrame); err != nil {
		return First, nil, err
	}
	packet, err := DecodePacket(raw, boundary.MaxFrame)
	if err != nil {
		return First, nil, err
	}
	// Decode and bind the signed Core without exposing it to either callback.
	signedCore := packet.Core()
	if accepts != nil && !accepts(packet.Core()) {
		return First, nil, ErrVersion
	}
	if err = AdmitPacket(packet, profile, boundary); err != nil {
		return First, nil, err
	}
	if !attest(packet.Core()) {
		return First, nil, ErrSource
	}
	decodedOperands, err := DecodeOperands(signedCore, boundary.MaxNesting)
	if err != nil {
		return First, nil, err
	}
	packet.decodedOperands = &decodedOperands
	key, err := Key(signedCore)
	if err != nil {
		return First, nil, err
	}
	arrival, err := store.bind(key, packet.exact)
	if err != nil {
		return First, nil, err
	}
	return arrival, packet, nil
}
