// Copyright 2022 The go-ethereum Authors
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

package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"

	"github.com/ethereum/go-ethereum/log"
)

//go:generate go run github.com/fjl/gencodec -type account -field-override accountMarshaling -out gen_account_json.go

// func init() {
// 	vm.DefaultDirectory.Register("prestateTracer", NewExecutionPrestateTracer, false)
// }

func getTracerExecutionResult(dt vm.DynamicTracer) (vm.DiffTracerResult, error) {
	// Get results
	res, err := dt.GetDiffTracerResult()

	return res, err
}

func getTracerExecutionCall(tracer vm.DynamicTracer) (CallTrace, error) {
	// Get results
	res, err := tracer.GetResult()
	var trace CallTrace
	json.Unmarshal(res, &trace)
	if err != nil {
		fmt.Println("Error unmarshalling:", err)
	}

	return trace, err
}

// Solidity version of the Diff Tracer Result

// type KeyValuePairSolidity struct {
// 	Key   common.Hash
// 	Value common.Hash
// }

// helper to convert objects
func flattenStorageData(storage map[common.Hash]common.Hash) ([]common.Hash, []common.Hash) {
	var storageKeys []common.Hash
	var storageValues []common.Hash

	if storage == nil {
		return []common.Hash{}, []common.Hash{}
	} else {
		for key, value := range storage {
			storageKeys = append(storageKeys, key)
			storageValues = append(storageValues, value)
		}
	}
	return storageKeys, storageValues
}

// func (result DiffTracerResult) ConvertToSolidity() DiffTracerResultSolidity {
// 	var resultSolidity DiffTracerResultSolidity

// 	// Convert Pre map to slice
// 	for _, account := range result.Pre {
// 		accountSolidity := TracerAccountSolidity{
// 			Balance: account.Balance,
// 			Storage: flattenStorageData(account.Storage),
// 		}
// 		resultSolidity.Pre = append(resultSolidity.Pre, accountSolidity)
// 	}

// 	// Convert Post map to slice
// 	for _, account := range result.Post {
// 		accountSolidity := TracerAccountSolidity{
// 			Balance: account.Balance,
// 			Storage: flattenStorageData(account.Storage),
// 		}
// 		resultSolidity.Post = append(resultSolidity.Post, accountSolidity)
// 	}

// 	return resultSolidity
// }

// func ConvertPreOrPostToSolidity(pre map[common.Address]TracerAccount) []TracerAccountSolidity {
// 	var resultSolidity []TracerAccountSolidity

// 	// Convert Pre map to slice
// 	for _, account := range pre {
// 		storageKeys, storageValues := flattenStorageData(account.Storage)
// 		accountSolidity := TracerAccountSolidity{
// 			Balance:       account.Balance,
// 			StorageKeys:   storageKeys,
// 			StorageValues: storageValues,
// 		}
// 		resultSolidity = append(resultSolidity, accountSolidity)
// 	}

// 	return resultSolidity
// }

func ConvertEventsToSolidity(events []vm.EventData) *[]vm.EventData {
	arr := make([]vm.EventData, len(events))
	for i, event := range events {
		arr[i] = vm.EventData{
			EventSigHash: event.EventSigHash,
			Parameters:   event.Parameters,
			Caller:       event.Caller,
		}
	}
	return &arr
}

func ConvertTracerResultToSolidity(address common.Address, tracerAccount vm.TracerAccount) vm.TracerAccountSolidity {

	// Ensure the value isn't nil
	var newbalance *uint256.Int

	if tracerAccount.Balance == nil {
		newbalance = uint256.NewInt(0)

	} else {
		newbalance = tracerAccount.Balance
	}
	storageKeys, storageValues := flattenStorageData(tracerAccount.Storage)
	// Convert Pre map to slice
	accountSolidity := vm.TracerAccountSolidity{
		Balance:       newbalance,
		StorageKeys:   storageKeys,
		StorageValues: storageValues,
	}
	// accountSolidity := TracerAccountSolidityLower{
	// 	balance:       newbalance,
	// 	storageKeys:   storageKeys,
	// 	storageValues: storageValues,
	// }

	return accountSolidity
}

type ExecutionPrestateTracer struct {
	env       *vm.EVM
	pre       map[common.Address]*vm.TracerAccount
	post      map[common.Address]*vm.TracerAccount
	events    map[common.Address]*[]vm.EventData
	create    bool
	to        common.Address
	gasLimit  uint64 // Amount of gas bought for the whole tx
	config    ExecutionPrestateTracerConfig
	interrupt atomic.Bool // Atomic flag to signal execution interruption
	reason    error       // Textual reason for the interruption
	created   map[common.Address]bool
	deleted   map[common.Address]bool
}

type ExecutionPrestateTracerConfig struct {
	DiffMode bool `json:"diffMode"` // If true, this tracer will return state modifications
}

func newExecutionPrestateTracer(cfg json.RawMessage) (vm.DynamicTracer, error) {
	var config ExecutionPrestateTracerConfig
	if cfg != nil {
		if err := json.Unmarshal(cfg, &config); err != nil {
			return nil, err
		}
	}
	return &ExecutionPrestateTracer{
		pre:     map[common.Address]*vm.TracerAccount{},
		post:    map[common.Address]*vm.TracerAccount{},
		events:  map[common.Address]*[]vm.EventData{},
		config:  config,
		created: make(map[common.Address]bool),
		deleted: make(map[common.Address]bool),
	}, nil
}

func NewExecutionPrestateTracer(cfg json.RawMessage) (vm.DynamicTracer, error) {
	var config ExecutionPrestateTracerConfig
	if cfg != nil {
		if err := json.Unmarshal(cfg, &config); err != nil {
			return nil, err
		}
	}
	return &ExecutionPrestateTracer{
		pre:     map[common.Address]*vm.TracerAccount{},
		post:    map[common.Address]*vm.TracerAccount{},
		events:  map[common.Address]*[]vm.EventData{},
		config:  config,
		created: make(map[common.Address]bool),
		deleted: make(map[common.Address]bool),
	}, nil
}

// CaptureStart implements the EVMLogger interface to initialize the tracing operation.
func (t *ExecutionPrestateTracer) CaptureStart(env *vm.EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *uint256.Int) {
	t.env = env
	t.create = create
	t.to = to

	// create events elements
	t.events = make(map[common.Address]*[]vm.EventData)
	t.events[to] = &[]vm.EventData{}
	t.events[from] = &[]vm.EventData{}

	t.lookupAccount(from)
	t.lookupAccount(to)
	t.lookupAccount(env.Context.Coinbase)

	// The recipient balance includes the value transferred.
	toBal := new(uint256.Int).Sub(t.pre[to].Balance, value)
	t.pre[to].Balance = toBal

	// The sender balance is after reducing: value and gasLimit.
	// We need to re-add them to get the pre-tx balance.
	fromBal := new(uint256.Int).Set(t.pre[from].Balance)
	gasPrice := env.TxContext.GasPrice
	consumedGas := new(big.Int).Mul(gasPrice, new(big.Int).SetUint64(t.gasLimit))
	var consumedGas256 *uint256.Int
	consumedGas256.SetFromBig(consumedGas)
	fromBal.Add(fromBal, new(uint256.Int).Add(value, consumedGas256))
	t.pre[from].Balance = fromBal
	t.pre[from].Nonce--

	if create && t.config.DiffMode {
		t.created[to] = true
	}
}

// CaptureEnd is called after the call finishes to finalize the tracing.
func (t *ExecutionPrestateTracer) CaptureEnd(output []byte, gasUsed uint64, err error) {
	if t.config.DiffMode {
		return
	}

	if t.create {
		// Keep existing account prior to contract creation at that address
		if s := t.pre[t.to]; s != nil && !s.Exists() {
			// Exclude newly created contract.
			delete(t.pre, t.to)
		}
	}
}

// CaptureState implements the EVMLogger interface to trace a single step of VM execution.
func (t *ExecutionPrestateTracer) CaptureState(pc uint64, op vm.OpCode, gas, cost uint64, scope *vm.ScopeContext, rData []byte, depth int, err error) {
	if err != nil {
		return
	}
	// Skip if tracing was interrupted
	if t.interrupt.Load() {
		return
	}
	stack := scope.Stack
	stackData := stack.Data()
	stackLen := len(stackData)
	currentContractAddress := scope.Contract.Address()
	caller := scope.Contract.Caller()

	switch {
	case op >= vm.LOG0 && op <= vm.LOG4:
		// Determine the number of indexed topics from the opcode
		numTopics := int(op - vm.LOG0)

		if err != nil {
			log.Warn("failed to copy LOG data", "err", err)
			return
		}

		// Construct the EventData with the correct size for topics and log data
		event := vm.EventData{
			EventSigHash: common.BytesToHash(stackData[stackLen-3].Bytes()),
			Parameters:   make([]common.Hash, numTopics),
			Caller:       caller,
		}

		for i := 0; i < numTopics; i++ {
			topic := stackData[stackLen-3-i].Bytes()
			event.Parameters[i] = common.BytesToHash(topic)
		}

		// Check if the address is present in the map
		if eventDataSlice, ok := t.events[currentContractAddress]; ok && eventDataSlice != nil {
			// Address is present and the slice is not nil, append the new EventData
			*eventDataSlice = append(*eventDataSlice, event)
		} else {
			// Address is not present or the slice is nil, create a new slice
			t.events[currentContractAddress] = &[]vm.EventData{event}
		}

	case stackLen >= 1 && (op == vm.SLOAD || op == vm.SSTORE):
		slot := common.Hash(stackData[stackLen-1].Bytes32())
		t.lookupStorage(currentContractAddress, slot)
	case stackLen >= 1 && (op == vm.EXTCODECOPY || op == vm.EXTCODEHASH || op == vm.EXTCODESIZE || op == vm.BALANCE || op == vm.SELFDESTRUCT):
		addr := common.Address(stackData[stackLen-1].Bytes20())
		t.lookupAccount(addr)
		if op == vm.SELFDESTRUCT {
			t.deleted[currentContractAddress] = true
		}
	case stackLen >= 5 && (op == vm.DELEGATECALL || op == vm.CALL || op == vm.STATICCALL || op == vm.CALLCODE):
		addr := common.Address(stackData[stackLen-2].Bytes20())
		t.lookupAccount(addr)
	case op == vm.CREATE:
		nonce := t.env.ExecutionDB.GetNonce(currentContractAddress)
		addr := crypto.CreateAddress(currentContractAddress, nonce)
		t.lookupAccount(addr)
		t.created[addr] = true
	case stackLen >= 4 && op == vm.CREATE2:
		offset := stackData[stackLen-2]
		size := stackData[stackLen-3]
		init, err := vm.GetMemoryCopyPadded(scope.Memory, int64(offset.Uint64()), int64(size.Uint64()))
		if err != nil {
			log.Warn("failed to copy CREATE2 input", "err", err, "tracer", "prestateTracer", "offset", offset, "size", size)
			return
		}
		inithash := crypto.Keccak256(init)
		salt := stackData[stackLen-4]
		addr := crypto.CreateAddress2(currentContractAddress, salt.Bytes32(), inithash)
		t.lookupAccount(addr)
		t.created[addr] = true
	}
}

func (t *ExecutionPrestateTracer) CaptureTxStart(gasLimit uint64) {
	t.gasLimit = gasLimit
}

func (t *ExecutionPrestateTracer) CaptureTxEnd(restGas uint64) {
	if !t.config.DiffMode {
		return
	}
	// vm.DebugPrint(t.pre)
	for addr, state := range t.pre {

		// The deleted account's state is pruned from `post` but kept in `pre`
		if _, ok := t.deleted[addr]; ok {
			continue
		}
		modified := false
		postAccount := &vm.TracerAccount{Storage: make(map[common.Hash]common.Hash)}
		newBalance := t.env.ExecutionDB.GetBalance(addr)
		newNonce := t.env.ExecutionDB.GetNonce(addr)
		newCode := t.env.ExecutionDB.GetCode(addr)

		if newBalance.Cmp(t.pre[addr].Balance) != 0 {
			modified = true
			postAccount.Balance = newBalance
		}
		if newNonce != t.pre[addr].Nonce {
			modified = true
			postAccount.Nonce = newNonce
		}
		if !bytes.Equal(newCode, t.pre[addr].Code) {
			modified = true
			postAccount.Code = newCode
		}

		for key, val := range state.Storage {
			// don't include the empty slot
			// if val == (common.Hash{}) {
			// 	delete(t.pre[addr].Storage, key)
			// }

			newVal := t.env.ExecutionDB.GetState(addr, key)
			if val == newVal {
				// Omit unchanged slots
				delete(t.pre[addr].Storage, key)
			} else {
				modified = true
				if newVal != (common.Hash{}) {
					postAccount.Storage[key] = newVal
				}
			}
		}

		if modified {
			t.post[addr] = postAccount
		} else {
			// if state is not modified, then no need to include into the pre state
			delete(t.pre, addr)
		}
	}
	// the new created contracts' prestate were empty, so delete them
	for a := range t.created {
		// the created contract maybe exists in statedb before the creating tx
		if s := t.pre[a]; s != nil && !s.Exists() {
			delete(t.pre, a)
		}
	}
}

// CaptureEnter is called when EVM enters a new scope (via call, create or selfdestruct).
func (t *ExecutionPrestateTracer) CaptureEnter(typ vm.OpCode, from common.Address, to common.Address, input []byte, gas uint64, value *uint256.Int) {
	log.Debug("EVM Entering", "contract address", to)
}

func (t *ExecutionPrestateTracer) GetDiffTracerResult() (vm.DiffTracerResult, error) {
	var res vm.DiffTracerResult
	var err error
	if t.config.DiffMode {
		res = vm.DiffTracerResult{Post: t.post, Pre: t.pre, Events: t.events}
	} else {
		res = vm.DiffTracerResult{Pre: t.pre, Events: t.events}
	}
	return res, err
}

// GetResult returns the json-encoded nested list of call traces, and any
// error arising from the encoding or forceful termination (via `Stop`).
func (t *ExecutionPrestateTracer) GetResult() (json.RawMessage, error) {
	var res []byte
	var err error
	if t.config.DiffMode {
		res, err = json.Marshal(struct {
			Post   map[common.Address]*vm.TracerAccount `json:"post"`
			Pre    map[common.Address]*vm.TracerAccount `json:"pre"`
			Events map[common.Address]*[]vm.EventData
		}{t.post, t.pre, t.events})
	} else {
		res, err = json.Marshal(struct {
			Pre    map[common.Address]*vm.TracerAccount `json:"pre"`
			Events map[common.Address]*[]vm.EventData
		}{t.pre, t.events})
	}
	if err != nil {
		return nil, err
	}
	return json.RawMessage(res), t.reason
}

// Stop terminates execution of the tracer at the first opportune moment.
func (t *ExecutionPrestateTracer) Stop(err error) {
	t.reason = err
	t.interrupt.Store(true)
}

// lookupAccount fetches details of an account and adds it to the prestate
// if it doesn't exist there.
func (t *ExecutionPrestateTracer) lookupAccount(addr common.Address) {
	if _, ok := t.pre[addr]; ok {
		return
	}

	t.pre[addr] = &vm.TracerAccount{
		Balance: t.env.ExecutionDB.GetBalance(addr),
		Nonce:   t.env.ExecutionDB.GetNonce(addr),
		Code:    t.env.ExecutionDB.GetCode(addr),
		Storage: make(map[common.Hash]common.Hash),
	}
}

// lookupStorage fetches the requested storage slot and adds
// it to the prestate of the given contract. It assumes `lookupAccount`
// has been performed on the contract before.
func (t *ExecutionPrestateTracer) lookupStorage(addr common.Address, key common.Hash) {

	if _, ok := t.pre[addr].Storage[key]; ok {
		return
	}
	t.pre[addr].Storage[key] = t.env.ExecutionDB.GetState(addr, key)
}

func (trace CallTrace) DebugCallTrace(indent int) {
	fmt.Println("%Debugging Trace")
	indentStr := ""
	for i := 0; i < indent; i++ {
		indentStr += "  "
	}

	fmt.Printf("%sFrom: %s\n", indentStr, trace.From.Hex())
	fmt.Printf("%sGas: %d\n", indentStr, trace.Gas)
	fmt.Printf("%sGas Used: %d\n", indentStr, trace.GasUsed)
	if trace.To != nil {
		fmt.Printf("%sTo: %s\n", indentStr, trace.To.Hex())
	}
	fmt.Printf("%sInput: %x\n", indentStr, trace.Input)
	fmt.Printf("%sOutput: %x\n", indentStr, trace.Output)
	fmt.Printf("%sError: %s\n", indentStr, trace.Error)
	fmt.Printf("%sRevert Reason: %s\n", indentStr, trace.RevertReason)
	if trace.Value != nil {
		fmt.Printf("%sValue: %d\n", indentStr, trace.Value.ToInt())
	}
	fmt.Printf("%sType: %s\n", indentStr, trace.Type)

	if len(trace.Calls) > 0 {
		fmt.Printf("%sCalls:\n", indentStr)
		for _, call := range trace.Calls {
			call.DebugCallTrace(indent + 1)
		}
	}

	if len(trace.Logs) > 0 {
		fmt.Printf("%sLogs:\n", indentStr)
		for _, log := range trace.Logs {
			fmt.Printf("log: %x\n", log)
		}
	}
}

// func (a *TracerAccountSolidity) UnmarshalTracerAccountSolidityJSON(data []byte) error {
// 	type Alias TracerAccountSolidity
// 	aux := &struct {
// 		Balance       string   `json:"balance,omitempty"`
// 		StorageKeys   []string `json:"storageKeys,omitempty"`
// 		StorageValues []string `json:"storageValues,omitempty"`
// 		*Alias
// 	}{
// 		Alias: (*Alias)(a),
// 	}
// 	if err := json.Unmarshal(data, &aux); err != nil {
// 		return err
// 	}

// 	// Convert hex string to big.Int for Balance
// 	a.Balance, _ = new(big.Int).SetString(aux.Balance[2:], 16)

// 	// Convert hex strings to common.Hash for StorageKeys and StorageValues
// 	for _, s := range aux.StorageKeys {
// 		a.StorageKeys = append(a.StorageKeys, common.HexToHash(s))
// 	}
// 	for _, s := range aux.StorageValues {
// 		a.StorageValues = append(a.StorageValues, common.HexToHash(s))
// 	}

// 	return nil
// }

// CaptureExit is called when EVM exits a scope, even if the scope didn't
// execute any code.
func (t *ExecutionPrestateTracer) CaptureExit(output []byte, gasUsed uint64, err error) {
}

// CaptureFault implements the EVMLogger interface to trace an execution fault.
func (t *ExecutionPrestateTracer) CaptureFault(pc uint64, op vm.OpCode, gas, cost uint64, _ *vm.ScopeContext, depth int, err error) {
}
