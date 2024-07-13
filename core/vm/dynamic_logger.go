// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// EVMLogger is used to collect execution traces from an EVM transaction
// execution. CaptureState is called for each step of the VM with the
// current VM state.
// Note that reference types are actual VM data structures; make copies
// if you need to retain them beyond the current call.
type ExecutionEVMLogger interface {
	// Transaction level
	CaptureTxStart(gasLimit uint64)
	CaptureTxEnd(restGas uint64)
	// Top call frame
	CaptureStart(env *EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int)
	CaptureEnd(output []byte, gasUsed uint64, err error)
	// Rest of call frames
	CaptureEnter(typ OpCode, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int)
	CaptureExit(output []byte, gasUsed uint64, err error)
	// Opcode level
	CaptureState(pc uint64, op OpCode, gas, cost uint64, scope *ScopeContext, rData []byte, depth int, err error)
	CaptureFault(pc uint64, op OpCode, gas, cost uint64, scope *ScopeContext, depth int, err error)
}

// EVMLoggerContext contains some contextual infos for a transaction execution that is not
// available from within the EVM object.
type ExecutionEVMLoggerContext struct {
	BlockHash   common.Hash // Hash of the block the tx is contained within (zero if dangling tx or call)
	BlockNumber *big.Int    // Number of the block the tx is contained within (zero if dangling tx or call)
	TxIndex     int         // Index of the transaction within a block (zero if dangling tx or call)
	TxHash      common.Hash // Hash of the transaction being traced (zero if dangling call)
}

// Tracer interface extends vm.EVMLogger and additionally
// allows collecting the tracing result.
type DynamicTracer interface {
	ExecutionEVMLogger
	GetResult() (json.RawMessage, error)
	GetDiffTracerResult() (DiffTracerResult, error)
	// Stop terminates execution of the tracer at the first opportune moment.
	Stop(err error)
}

func getTracerExecutionResult(tracer DynamicTracer) (DiffTracerResult, error) {
	// Get results
	res, err := tracer.GetDiffTracerResult()

	return res, err
}

type ctorFn func(*ExecutionEVMLoggerContext, json.RawMessage) (DynamicTracer, error)
type jsCtorFn func(string, *ExecutionEVMLoggerContext, json.RawMessage) (DynamicTracer, error)

type elem struct {
	ctor ctorFn
	isJS bool
}

// // DefaultDirectory is the collection of tracers bundled by default.
// var DefaultDirectory = directory{elems: make(map[string]elem)}

// // directory provides functionality to lookup a tracer by name
// // and a function to instantiate it. It falls back to a JS code evaluator
// // if no tracer of the given name exists.
// type directory struct {
// 	elems  map[string]elem
// 	jsEval jsCtorFn
// }

// // New returns a new instance of a tracer, by iterating through the
// // registered lookups. Name is either name of an existing tracer
// // or an arbitrary JS code.
// func (d *directory) New(name string, ctx *ExecutionEVMLoggerContext, cfg json.RawMessage) (ExecutionTracer, error) {
// 	if elem, ok := d.elems[name]; ok {
// 		return elem.ctor(ctx, cfg)
// 	}
// 	// Assume JS code
// 	return d.jsEval(name, ctx, cfg)
// }

// // IsJS will return true if the given tracer will evaluate
// // JS code. Because code evaluation has high overhead, this
// // info will be used in determining fast and slow code paths.
// func (d *directory) IsJS(name string) bool {
// 	if elem, ok := d.elems[name]; ok {
// 		return elem.isJS
// 	}
// 	// JS eval will execute JS code
// 	return true
// }

const (
	memoryPadLimit = 1024 * 1024
)

// GetMemoryCopyPadded returns offset + size as a new slice.
// It zero-pads the slice if it extends beyond memory bounds.
func GetMemoryCopyPadded(m *Memory, offset, size int64) ([]byte, error) {
	if offset < 0 || size < 0 {
		return nil, errors.New("offset or size must not be negative")
	}
	if int(offset+size) < m.Len() { // slice fully inside memory
		return m.GetCopy(offset, size), nil
	}
	paddingNeeded := int(offset+size) - m.Len()
	if paddingNeeded > memoryPadLimit {
		return nil, fmt.Errorf("reached limit for padding memory slice: %d", paddingNeeded)
	}
	cpy := make([]byte, size)
	if overlap := int64(m.Len()) - offset; overlap > 0 {
		copy(cpy, m.GetPtr(offset, overlap))
	}
	return cpy, nil
}

type DiffTracerResult struct {
	Post   map[common.Address]*TracerAccount `json:"post"`
	Pre    map[common.Address]*TracerAccount `json:"pre"`
	Events map[common.Address]*[]EventData   `json:"events,omitempty"`
}

// this is sent to the security smart contract for analysis.
type TracerAccountSolidity struct {
	Balance       *big.Int      `json:"balance,omitempty"`
	StorageKeys   []common.Hash `json:"storageKeys,omitempty"`
	StorageValues []common.Hash `json:"storageValues,omitempty"`
}

type DiffTracerResultSolidity struct {
	Pre    []TracerAccountSolidity `json:"pre"`
	Post   []TracerAccountSolidity `json:"post"`
	Events []EventData             `json:"events,omitempty"`
}

// Go Version of the  Diff Tracer Result
type TracerAccount struct {
	Balance *big.Int                    `json:"balance,omitempty"`
	Code    []byte                      `json:"code,omitempty"`
	Nonce   uint64                      `json:"nonce,omitempty"`
	Storage map[common.Hash]common.Hash `json:"storage,omitempty"`
}

// Event data to be used by tracer.
// this is sent to the security smart contract for analysis.
type EventData struct {
	EventSigHash common.Hash
	Parameters   []common.Hash
	Caller       common.Address
}

func (a *TracerAccount) Exists() bool {
	return a.Nonce > 0 || len(a.Code) > 0 || len(a.Storage) > 0 || (a.Balance != nil && a.Balance.Sign() != 0)
}

// UnmarshalJSON unmarshals from JSON.
func (a *TracerAccount) UnmarshalJSON(input []byte) error {
	type account struct {
		Balance *hexutil.Big                `json:"balance,omitempty"`
		Code    *hexutil.Bytes              `json:"code,omitempty"`
		Nonce   *uint64                     `json:"nonce,omitempty"`
		Storage map[common.Hash]common.Hash `json:"storage,omitempty"`
	}
	var dec account
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	if dec.Balance != nil {
		a.Balance = (*big.Int)(dec.Balance)
	}
	if dec.Code != nil {
		a.Code = *dec.Code
	}
	if dec.Nonce != nil {
		a.Nonce = *dec.Nonce
	}
	if dec.Storage != nil {
		a.Storage = dec.Storage
	}
	return nil
}

func (t *TracerAccount) DebugPrint() {
	fmt.Printf("Balance: %s\n", t.Balance.Text(16)) // Print balance in hexadecimal
	fmt.Printf("Nonce: %x\n", t.Nonce)              // Print nonce in hexadecimal

	fmt.Println("Storage:")
	for key, value := range t.Storage {
		fmt.Printf("Key: %s, Value: %s\n", key.Hex(), value.Hex())
	}
}

func DebugPrint(t map[common.Address]*TracerAccount) {
	for addr, tracer := range t {
		fmt.Printf("Address: %s\n", addr)
		tracer.DebugPrint()
	}
}

func (t *TracerAccountSolidity) DebugPrint() {
	fmt.Printf("Balance: %s\n", t.Balance.Text(16)) // Print balance in hexadecimal

	fmt.Println("Storage:")
	for index, _ := range t.StorageKeys {
		fmt.Printf("Key: %s, Value: %s\n", t.StorageKeys[index].Hex(), t.StorageValues[index].Hex())
	}
}

func (d *DiffTracerResult) DebugPrint() {
	fmt.Println("")
	fmt.Println("\nDiff Tracer Pre")
	for address, tracer := range d.Pre {
		fmt.Printf("Address: %s\n", address)
		tracer.DebugPrint()
	}
	fmt.Println("\nDiff Tracer Post")
	for address, tracer := range d.Post {
		fmt.Printf("Address: %s\n", address)
		tracer.DebugPrint()
	}

}
func (d *DiffTracerResultSolidity) DebugPrint() {
	fmt.Println("")
	fmt.Println("\nDiff Tracer Solidity Pre")
	for _, tracer := range d.Pre {

		tracer.DebugPrint()
	}
	fmt.Println("\nDiff Tracer Solidity Post")
	for _, tracer := range d.Post {

		tracer.DebugPrint()
	}

}

// MarshalJSON marshals as JSON.
func (a TracerAccount) MarshalJSON() ([]byte, error) {
	type account struct {
		Balance *hexutil.Big                `json:"balance,omitempty"`
		Code    hexutil.Bytes               `json:"code,omitempty"`
		Nonce   uint64                      `json:"nonce,omitempty"`
		Storage map[common.Hash]common.Hash `json:"storage,omitempty"`
	}
	var enc account
	enc.Balance = (*hexutil.Big)(a.Balance)
	enc.Code = a.Code
	enc.Nonce = a.Nonce
	enc.Storage = a.Storage
	return json.Marshal(&enc)
}

func areTracerAccountsEqual(a, b *TracerAccount) bool {
	return a.Balance.Cmp(b.Balance) == 0 &&
		reflect.DeepEqual(a.Code, b.Code) &&
		a.Nonce == b.Nonce &&
		reflect.DeepEqual(a.Storage, b.Storage)
}

func AreDiffTracerResultsEqual(a, b *DiffTracerResult) bool {
	if len(a.Post) != len(b.Post) || len(a.Pre) != len(b.Pre) {
		return false
	}

	for addr, accA := range a.Post {
		accB, exists := b.Post[addr]
		if !exists || !areTracerAccountsEqual(accA, accB) {
			return false
		}
	}

	for addr, accA := range a.Pre {
		accB, exists := b.Pre[addr]
		if !exists || !areTracerAccountsEqual(accA, accB) {
			return false
		}
	}

	return true
}
