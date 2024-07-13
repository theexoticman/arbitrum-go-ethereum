// Copyright 2014 The go-ethereum Authors
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
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	cmath "github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
)

// ExecutionResult includes all output after executing given evm
// message no matter the execution itself is successful or not.
type ExecutionResult struct {
	UsedGas    uint64 // Total used gas but include the refunded gas
	Err        error  // Any error encountered during the execution(listed in core/vm/errors.go)
	ReturnData []byte // Returned data from evm(function result or data supplied with revert opcode)

	// Arbitrum: a tx may yield others that need to run afterward (see retryables)
	ScheduledTxes types.Transactions
	// Arbitrum: the contract deployed from the top-level transaction, or nil if not a contract creation tx
	TopLevelDeployed *common.Address
}

// Unwrap returns the internal evm error which allows us for further
// analysis outside.
func (result *ExecutionResult) Unwrap() error {
	return result.Err
}

// Failed returns the indicator whether the execution is successful or not
func (result *ExecutionResult) Failed() bool { return result.Err != nil }

// FailedButFirewall returns the indicator whether the execution is successful or not,
// without considering the firewall. a firewall error is ok from the evm stand point.
func (result *ExecutionResult) FailedButFirewall(err error) bool {
	return result.Err != nil && !errors.Is(err, vm.ErrSecurityFirewallRevert)
}

// Return is a helper function to help caller distinguish between revert reason
// and function return. Return returns the data after execution if no error occurs.
func (result *ExecutionResult) Return() []byte {
	if result.Err != nil {
		return nil
	}
	return common.CopyBytes(result.ReturnData)
}

// Revert returns the concrete revert reason if the execution is aborted by `REVERT`
// opcode. Note the reason can be nil if no data supplied with revert opcode.
func (result *ExecutionResult) Revert() []byte {
	if result.Err != vm.ErrExecutionReverted {
		return nil
	}
	return common.CopyBytes(result.ReturnData)
}

var security_reason = "ipschainsecurity"

// IntrinsicGas computes the 'intrinsic gas' for a message with the given data.
func IntrinsicGas(data []byte, accessList types.AccessList, isContractCreation bool, isHomestead, isEIP2028 bool, isEIP3860 bool) (uint64, error) {
	// Set the starting gas for the raw transaction
	var gas uint64
	if isContractCreation && isHomestead {
		gas = params.TxGasContractCreation
	} else {
		gas = params.TxGas
	}
	dataLen := uint64(len(data))
	// Bump the required gas by the amount of transactional data
	if dataLen > 0 {
		// Zero and non-zero bytes are priced differently
		var nz uint64
		for _, byt := range data {
			if byt != 0 {
				nz++
			}
		}
		// Make sure we don't exceed uint64 for all data combinations
		nonZeroGas := params.TxDataNonZeroGasFrontier
		if isEIP2028 {
			nonZeroGas = params.TxDataNonZeroGasEIP2028
		}
		if (math.MaxUint64-gas)/nonZeroGas < nz {
			return 0, ErrGasUintOverflow
		}
		gas += nz * nonZeroGas

		z := dataLen - nz
		if (math.MaxUint64-gas)/params.TxDataZeroGas < z {
			return 0, ErrGasUintOverflow
		}
		gas += z * params.TxDataZeroGas

		if isContractCreation && isEIP3860 {
			lenWords := toWordSize(dataLen)
			if (math.MaxUint64-gas)/params.InitCodeWordGas < lenWords {
				return 0, ErrGasUintOverflow
			}
			gas += lenWords * params.InitCodeWordGas
		}
	}
	if accessList != nil {
		gas += uint64(len(accessList)) * params.TxAccessListAddressGas
		gas += uint64(accessList.StorageKeys()) * params.TxAccessListStorageKeyGas
	}
	return gas, nil
}

// toWordSize returns the ceiled word size required for init code payment calculation.
func toWordSize(size uint64) uint64 {
	if size > math.MaxUint64-31 {
		return math.MaxUint64/32 + 1
	}

	return (size + 31) / 32
}

// A Message contains the data derived from a single transaction that is relevant to state
// processing.
type Message struct {
	// Arbitrum-specific
	TxRunMode MessageRunMode
	Tx        *types.Transaction

	To            *common.Address
	From          common.Address
	Nonce         uint64
	Value         *big.Int
	GasLimit      uint64
	GasPrice      *big.Int
	GasFeeCap     *big.Int
	GasTipCap     *big.Int
	Data          []byte
	AccessList    types.AccessList
	BlobGasFeeCap *big.Int
	BlobHashes    []common.Hash

	// When SkipAccountChecks is true, the message nonce is not checked against the
	// account nonce in state. It also disables checking that the sender is an EOA.
	// This field will be set to true for operations like RPC eth_call.
	SkipAccountChecks bool
	// L1 charging is disabled when SkipL1Charging is true.
	// This field might be set to true for operations like RPC eth_call.
	SkipL1Charging bool
}

type MessageRunMode uint8

const (
	MessageCommitMode MessageRunMode = iota
	MessageGasEstimationMode
	MessageEthcallMode
)

// TransactionToMessage converts a transaction into a Message.
func TransactionToMessage(tx *types.Transaction, s types.Signer, baseFee *big.Int) (*Message, error) {
	msg := &Message{
		Tx: tx,

		Nonce:             tx.Nonce(),
		GasLimit:          tx.Gas(),
		GasPrice:          new(big.Int).Set(tx.GasPrice()),
		GasFeeCap:         new(big.Int).Set(tx.GasFeeCap()),
		GasTipCap:         new(big.Int).Set(tx.GasTipCap()),
		To:                tx.To(),
		Value:             tx.Value(),
		Data:              tx.Data(),
		AccessList:        tx.AccessList(),
		SkipAccountChecks: tx.SkipAccountChecks(), // TODO Arbitrum upstream this was init'd to false
		BlobHashes:        tx.BlobHashes(),
		BlobGasFeeCap:     tx.BlobGasFeeCap(),
	}
	// If baseFee provided, set gasPrice to effectiveGasPrice.
	if baseFee != nil {
		msg.GasPrice = cmath.BigMin(msg.GasPrice.Add(msg.GasTipCap, baseFee), msg.GasFeeCap)
	}
	var err error
	msg.From, err = types.Sender(s, tx)
	return msg, err
}

// ApplyMessage computes the new state by applying the given message
// against the old state within the environment.
//
// ApplyMessage returns the bytes returned by any EVM execution (if it took place),
// the gas used (which includes gas refunds) and an error if it failed. An error always
// indicates a core error meaning that the message would always fail for that particular
// state and would never be accepted within a block.
func ApplyMessage(evm *vm.EVM, msg *Message, gp *GasPool) (*ExecutionResult, error) {
	stateTransition := NewStateTransition(evm, msg, gp)
	executionResult, err := stateTransition.TransitionDb()
	if executionResult != nil && executionResult.Err == nil {
		// Regular transaction already reverted
		executionResult, err = stateTransition.runSecurityChecks(executionResult)
	}
	stateTransition.EndTxRefund()
	return executionResult, err
}

// StateTransition represents a state transition.
//
// == The State Transitioning Model
//
// A state transition is a change made when a transaction is applied to the current world
// state. The state transitioning model does all the necessary work to work out a valid new
// state root.
//
//  1. Nonce handling
//  2. Pre pay gas
//  3. Create a new state object if the recipient is nil
//  4. Value transfer
//  5. previous snapshot keeping for revert
//
// == If contract creation ==
//
//	4a. Attempt to run transaction data
//	4b. If valid, use result as code for the new state object
//
// == end ==
//
//  5. Run Script section
//  6. Derive new state root
type StateTransition struct {
	gp           *GasPool
	msg          *Message
	gasRemaining uint64
	initialGas   uint64
	state        vm.StateDB
	evm          *vm.EVM
}

// NewStateTransition initialises and returns a new state transition object.
func NewStateTransition(evm *vm.EVM, msg *Message, gp *GasPool) *StateTransition {
	if ReadyEVMForL2 != nil {
		ReadyEVMForL2(evm, msg)
	}

	return &StateTransition{
		gp:    gp,
		evm:   evm,
		msg:   msg,
		state: evm.StateDB,
	}
}

// to returns the recipient of the message.
func (st *StateTransition) to() common.Address {
	if st.msg == nil || st.msg.To == nil /* contract creation */ {
		return common.Address{}
	}
	return *st.msg.To
}

// to returns the recipient of the message.
// func (st *StateTransition) from() vm.ContractRef {
// 	if st.msg == nil {
// 		return nil
// 	}
// 	return vm.AccountRef(st.msg.From)
// }

func (st *StateTransition) buyGas() error {
	mgval := new(big.Int).SetUint64(st.msg.GasLimit)
	mgval = mgval.Mul(mgval, st.msg.GasPrice)
	balanceCheck := new(big.Int).Set(mgval)
	if st.msg.GasFeeCap != nil {
		balanceCheck.SetUint64(st.msg.GasLimit)
		balanceCheck = balanceCheck.Mul(balanceCheck, st.msg.GasFeeCap)
		balanceCheck.Add(balanceCheck, st.msg.Value)
	}
	if st.evm.ChainConfig().IsCancun(st.evm.Context.BlockNumber, st.evm.Context.Time, st.evm.Context.ArbOSVersion) {
		if blobGas := st.blobGasUsed(); blobGas > 0 {
			// Check that the user has enough funds to cover blobGasUsed * tx.BlobGasFeeCap
			blobBalanceCheck := new(big.Int).SetUint64(blobGas)
			blobBalanceCheck.Mul(blobBalanceCheck, st.msg.BlobGasFeeCap)
			balanceCheck.Add(balanceCheck, blobBalanceCheck)
			// Pay for blobGasUsed * actual blob fee
			blobFee := new(big.Int).SetUint64(blobGas)
			blobFee.Mul(blobFee, st.evm.Context.BlobBaseFee)
			mgval.Add(mgval, blobFee)
		}
	}
	if have, want := st.state.GetBalance(st.msg.From), balanceCheck; have.Cmp(want) < 0 {
		return fmt.Errorf("%w: address %v have %v want %v", ErrInsufficientFunds, st.msg.From.Hex(), have, want)
	}
	if err := st.gp.SubGas(st.msg.GasLimit); err != nil {
		return err
	}
	st.gasRemaining += st.msg.GasLimit

	st.initialGas = st.msg.GasLimit
	st.state.SubBalance(st.msg.From, mgval)

	// Arbitrum: record fee payment
	if tracer := st.evm.Config.Tracer; tracer != nil {
		tracer.CaptureArbitrumTransfer(st.evm, &st.msg.From, nil, mgval, true, "feePayment")
	}

	return nil
}

func (st *StateTransition) preCheck() error {
	// Only check transactions that are not fake
	msg := st.msg
	if !msg.SkipAccountChecks {
		// Make sure this transaction's nonce is correct.
		stNonce := st.state.GetNonce(msg.From)
		if msgNonce := msg.Nonce; stNonce < msgNonce {
			return fmt.Errorf("%w: address %v, tx: %d state: %d", ErrNonceTooHigh,
				msg.From.Hex(), msgNonce, stNonce)
		} else if stNonce > msgNonce {
			return fmt.Errorf("%w: address %v, tx: %d state: %d", ErrNonceTooLow,
				msg.From.Hex(), msgNonce, stNonce)
		} else if stNonce+1 < stNonce {
			return fmt.Errorf("%w: address %v, nonce: %d", ErrNonceMax,
				msg.From.Hex(), stNonce)
		}
		// Make sure the sender is an EOA
		codeHash := st.state.GetCodeHash(msg.From)
		if codeHash != (common.Hash{}) && codeHash != types.EmptyCodeHash {
			return fmt.Errorf("%w: address %v, codehash: %s", ErrSenderNoEOA,
				msg.From.Hex(), codeHash)
		}
	}

	// Make sure that transaction gasFeeCap is greater than the baseFee (post london)
	if st.evm.ChainConfig().IsLondon(st.evm.Context.BlockNumber) {
		// Skip the checks if gas fields are zero and baseFee was explicitly disabled (eth_call)
		if !st.evm.Config.NoBaseFee || msg.GasFeeCap.BitLen() > 0 || msg.GasTipCap.BitLen() > 0 {
			if l := msg.GasFeeCap.BitLen(); l > 256 {
				return fmt.Errorf("%w: address %v, maxFeePerGas bit length: %d", ErrFeeCapVeryHigh,
					msg.From.Hex(), l)
			}
			if l := msg.GasTipCap.BitLen(); l > 256 {
				return fmt.Errorf("%w: address %v, maxPriorityFeePerGas bit length: %d", ErrTipVeryHigh,
					msg.From.Hex(), l)
			}
			if msg.GasFeeCap.Cmp(msg.GasTipCap) < 0 {
				return fmt.Errorf("%w: address %v, maxPriorityFeePerGas: %s, maxFeePerGas: %s", ErrTipAboveFeeCap,
					msg.From.Hex(), msg.GasTipCap, msg.GasFeeCap)
			}
			// This will panic if baseFee is nil, but basefee presence is verified
			// as part of header validation.
			if msg.GasFeeCap.Cmp(st.evm.Context.BaseFee) < 0 {
				return fmt.Errorf("%w: address %v, maxFeePerGas: %s baseFee: %s", ErrFeeCapTooLow,
					msg.From.Hex(), msg.GasFeeCap, st.evm.Context.BaseFee)
			}
		}
	}
	// Check the blob version validity
	if msg.BlobHashes != nil {
		if len(msg.BlobHashes) == 0 {
			return errors.New("blob transaction missing blob hashes")
		}
		for i, hash := range msg.BlobHashes {
			if hash[0] != params.BlobTxHashVersion {
				return fmt.Errorf("blob %d hash version mismatch (have %d, supported %d)",
					i, hash[0], params.BlobTxHashVersion)
			}
		}
	}

	if st.evm.ChainConfig().IsCancun(st.evm.Context.BlockNumber, st.evm.Context.Time, st.evm.Context.ArbOSVersion) {
		if st.blobGasUsed() > 0 {
			// Check that the user is paying at least the current blob fee
			blobFee := st.evm.Context.BlobBaseFee
			if st.msg.BlobGasFeeCap.Cmp(blobFee) < 0 {
				return fmt.Errorf("%w: address %v have %v want %v", ErrBlobFeeCapTooLow, st.msg.From.Hex(), st.msg.BlobGasFeeCap, blobFee)
			}
		}
	}

	return st.buyGas()
}

// TransitionDb will transition the state by applying the current message and
// returning the evm execution result with following fields.
//
//   - used gas: total gas used (including gas being refunded)
//   - returndata: the returned data from evm
//   - concrete execution error: various EVM errors which abort the execution, e.g.
//     ErrOutOfGas, ErrExecutionReverted
//
// However if any consensus issue encountered, return the error directly with
// nil evm execution result.
func (st *StateTransition) TransitionDb() (*ExecutionResult, error) {
	endTxNow, startHookUsedGas, err, returnData := st.evm.ProcessingHook.StartTxHook()
	if endTxNow {
		return &ExecutionResult{
			UsedGas:       startHookUsedGas,
			Err:           err,
			ReturnData:    returnData,
			ScheduledTxes: st.evm.ProcessingHook.ScheduledTxes(),
		}, nil
	}

	// First check this message satisfies all consensus rules before
	// applying the message. The rules include these clauses
	//
	// 1. the nonce of the message caller is correct
	// 2. caller has enough balance to cover transaction fee(gaslimit * gasprice)
	// 3. the amount of gas required is available in the block
	// 4. the purchased gas is enough to cover intrinsic usage
	// 5. there is no overflow when calculating intrinsic gas
	// 6. caller has enough balance to cover asset transfer for **topmost** call

	// Arbitrum: drop tip for delayed (and old) messages
	if st.evm.ProcessingHook.DropTip() && st.msg.GasPrice.Cmp(st.evm.Context.BaseFee) > 0 {
		st.msg.GasPrice = st.evm.Context.BaseFee
		st.msg.GasTipCap = common.Big0
	}

	// Check clauses 1-3, buy gas if everything is correct
	if err := st.preCheck(); err != nil {
		return nil, err
	}

	if tracer := st.evm.Config.Tracer; tracer != nil {
		tracer.CaptureTxStart(st.initialGas)
		defer func() {
			tracer.CaptureTxEnd(st.gasRemaining)
		}()
	}

	// Dynamic tracing, new mechanism, unrelated to tracing when executing again via bebug api
	if dynamicTracer := st.evm.Config.DynamicTracer; dynamicTracer != nil {
		dynamicTracer.CaptureTxStart(st.initialGas)
		defer func() {
			dynamicTracer.CaptureTxEnd(st.gasRemaining)
		}()
	}

	var (
		msg              = st.msg
		sender           = vm.AccountRef(msg.From)
		rules            = st.evm.ChainConfig().Rules(st.evm.Context.BlockNumber, st.evm.Context.Random != nil, st.evm.Context.Time, st.evm.Context.ArbOSVersion)
		contractCreation = msg.To == nil
	)

	// Check clauses 4-5, subtract intrinsic gas if everything is correct
	gas, err := IntrinsicGas(msg.Data, msg.AccessList, contractCreation, rules.IsHomestead, rules.IsIstanbul, rules.IsShanghai)
	if err != nil {
		return nil, err
	}
	if st.gasRemaining < gas {
		return nil, fmt.Errorf("%w: have %d, want %d", ErrIntrinsicGas, st.gasRemaining, gas)
	}
	st.gasRemaining -= gas

	// Check clause 6
	if msg.Value.Sign() > 0 && !st.evm.Context.CanTransfer(st.state, msg.From, msg.Value) {
		return nil, fmt.Errorf("%w: address %v", ErrInsufficientFundsForTransfer, msg.From.Hex())
	}

	// Check whether the init code size has been exceeded.
	if rules.IsShanghai && contractCreation && len(msg.Data) > int(st.evm.ChainConfig().MaxInitCodeSize()) {
		return nil, fmt.Errorf("%w: code size %v limit %v", ErrMaxInitCodeSizeExceeded, len(msg.Data), int(st.evm.ChainConfig().MaxInitCodeSize()))
	}

	// Execute the preparatory steps for state transition which includes:
	// - prepare accessList(post-berlin)
	// - reset transient storage(eip 1153)
	st.state.Prepare(rules, msg.From, st.evm.Context.Coinbase, msg.To, vm.ActivePrecompiles(rules), msg.AccessList)

	var deployedContract *common.Address

	var (
		ret   []byte
		vmerr error // vm errors do not effect consensus and are therefore not assigned to err
	)
	if contractCreation {
		deployedContract = &common.Address{}
		ret, *deployedContract, st.gasRemaining, vmerr = st.evm.Create(sender, msg.Data, st.gasRemaining, msg.Value, true)
	} else {
		// Increment the nonce for the next transaction
		st.state.SetNonce(msg.From, st.state.GetNonce(sender.Address())+1)

		// Perform the contract call in the EVM
		ret, st.gasRemaining, vmerr = st.evm.Call(sender, st.to(), msg.Data, st.gasRemaining, msg.Value, true)

	}

	return &ExecutionResult{
		UsedGas:          st.gasUsed(),
		Err:              vmerr,
		ReturnData:       ret,
		ScheduledTxes:    st.evm.ProcessingHook.ScheduledTxes(),
		TopLevelDeployed: deployedContract,
	}, nil

}

func (st *StateTransition) EndTxRefund() error {
	tipAmount := big.NewInt(0)
	tipReceipient, err := st.evm.ProcessingHook.GasChargingHook(&st.gasRemaining)
	if err != nil {
		return err
	}
	rules := st.evm.ChainConfig().Rules(st.evm.Context.BlockNumber, st.evm.Context.Random != nil, st.evm.Context.Time, st.evm.Context.ArbOSVersion)

	if !rules.IsLondon {
		// Before EIP-3529: refunds were capped to gasUsed / 2
		st.refundGas(params.RefundQuotient)
	} else {
		// After EIP-3529: refunds are capped to gasUsed / 5
		st.refundGas(params.RefundQuotientEIP3529)
	}
	effectiveTip := st.msg.GasPrice
	if rules.IsLondon {
		effectiveTip = cmath.BigMin(st.msg.GasTipCap, new(big.Int).Sub(st.msg.GasFeeCap, st.evm.Context.BaseFee))
	}

	if st.evm.Config.NoBaseFee && st.msg.GasFeeCap.Sign() == 0 && st.msg.GasTipCap.Sign() == 0 {
		// Skip fee payment when NoBaseFee is set and the fee fields
		// are 0. This avoids a negative effectiveTip being applied to
		// the coinbase when simulating calls.
	} else {
		fee := new(big.Int).SetUint64(st.gasUsed())
		fee.Mul(fee, effectiveTip)
		st.state.AddBalance(tipReceipient, fee)
		tipAmount = fee
	}

	// Arbitrum: record the tip
	if tracer := st.evm.Config.Tracer; tracer != nil && !st.evm.ProcessingHook.DropTip() {
		tracer.CaptureArbitrumTransfer(st.evm, nil, &tipReceipient, tipAmount, false, "tip")
	}

	// Arbitrum: record self destructs
	if tracer := st.evm.Config.Tracer; tracer != nil {
		suicides := st.evm.StateDB.GetSelfDestructs()
		for i, address := range suicides {
			balance := st.evm.StateDB.GetBalance(address)
			tracer.CaptureArbitrumTransfer(st.evm, &suicides[i], nil, balance, false, "selfDestruct")
		}
	}
	return nil
}

func (st *StateTransition) runSecurityChecks(executionResult *ExecutionResult) (*ExecutionResult, error) {
	var (
		msg              = st.msg
		sender           = vm.AccountRef(msg.From)
		contractCreation = msg.To == nil
		securityVmerr    error // used for any error happening in the security checks
		ret              []byte
	)
	if st.evm.ChainConfig().IPSMode && (executionResult.Err == nil) {
		// Only execute Smart Contract Security tests if IPSMode is being used and if the transaction didn't fail

		if (!contractCreation) && (len(msg.Data) != 0) {
			// Tx is a contract call and not a creation.
			// Retrieve the trace result and compare against the expected
			diffTracerRes, err := getTracerExecutionResult(st.evm.Config.DynamicTracer)
			if err != nil {
				log.Fatalf("Failed to collect the transaction execution from diff tracer: %v", err)
			}
			if diffTracerRes.Post != nil && len(diffTracerRes.Post) > 0 {
				// check if snapshots were created  <=> contracts were modified
				// means that it is not a contract creation nor a contract read

				// if len(st.evm.StateToSnapshotMapping) > 0 {
				// for contractAddress, snapshotAddress := range st.evm.StateToSnapshotMapping {
				changedContracts := []common.Address{}
				for address, _ := range diffTracerRes.Post {
					// fmt.Printf(" ===> Modified contract: %x\n", address)
					changedContracts = append(changedContracts, address)
				}
				// only keep the contracts that changed
				for _, contractAddress := range changedContracts {
					snapshotAddress := st.evm.StateToSnapshotMapping[contractAddress]
					// fmt.Printf("  ====> addr : %x, snap: %x\n", contractAddress, snapshotAddress)
					// keccak
					securityAccountSlot := common.HexToHash("0xf5db7be7144a933071df54eb1557c996e91cbc47176ea78e1c6f39f9306cff5f")
					// Get security contract stored in smart contract
					securityContractAddressHash := st.evm.StateDB.GetState(contractAddress, securityAccountSlot)
					if securityContractAddressHash != (common.Hash{}) {
						// fmt.Printf(" ====> addr : %x, sec: %x\n", contractAddress, securityContractAddressHash)
						// Collecting Security Smart Contract
						var securityContractAddres common.Address
						copy(securityContractAddres[:], securityContractAddressHash[12:])

						// encoding security smart contract call
						inputData, err := encodeSecuritySmartContractParameterV1(st.msg.From, snapshotAddress, contractAddress, diffTracerRes.Events[contractAddress])

						// convert the parameters to compatible format

						if err != nil {
							log.Fatalf("Failed to encode security tests parameters : %v", err)
						}
						value := big.NewInt(0)
						ret, st.gasRemaining, securityVmerr = st.evm.Call(sender, securityContractAddres, inputData, st.gasRemaining, value, false)
						if securityVmerr != nil {
							// fail fast,
							executionResult.ReturnData = ret
							executionResult.Err = securityVmerr
							if len(ret) > 0 {
								reason := string(getSCRevertReason(ret))
								// fmt.Printf(" ====> reason : %s\n", reason)
								if strings.HasPrefix(reason, security_reason) {
									// failed for security reasons, set reason
									// to be ignored in the estimation.
									executionResult.Err = securityVmerr
									// quick hack as the err are supposed to be non evm related.
									return executionResult, vm.ErrSecurityFirewallRevert
								}
							}
						}
					}
				}
			}
		}
	}
	executionResult.UsedGas = st.gasUsed()
	return executionResult, nil
}

// func encodeSecuritySmartContractParameter(caller common.Address, pre vm.TracerAccountSolidity, post vm.TracerAccountSolidity, events *[]vm.EventData) ([]byte, error) {
// 	default_sec_fn := "runSecurityChecks"
// 	// TODO, the abi will be the same as the called smart contract. but function names will change with ips_ at beg. eg: ips_withdraw.
// 	securityAccountAbi := `[{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"caller","type":"address"}],"name":"Caller","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint256","name":"bought","type":"uint256"}],"name":"Revert","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"string","name":"moment","type":"string"},{"indexed":false,"internalType":"bytes32","name":"key","type":"bytes32"},{"indexed":false,"internalType":"bytes32","name":"value","type":"bytes32"}],"name":"StoredValue","type":"event"},{"inputs":[],"name":"GetDummy","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"caller","type":"address"},{"components":[{"internalType":"uint256","name":"balance","type":"uint256"},{"internalType":"bytes32[]","name":"storageKeys","type":"bytes32[]"},{"internalType":"bytes32[]","name":"storageValues","type":"bytes32[]"}],"internalType":"struct NFTVaultSecurityAccount.TracerAccountSolidityLower","name":"pre","type":"tuple"},{"components":[{"internalType":"uint256","name":"balance","type":"uint256"},{"internalType":"bytes32[]","name":"storageKeys","type":"bytes32[]"},{"internalType":"bytes32[]","name":"storageValues","type":"bytes32[]"}],"internalType":"struct NFTVaultSecurityAccount.TracerAccountSolidityLower","name":"post","type":"tuple"}],"name":"ips_buyNFT","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"name":"nftContractStoragePost","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"name":"nftContractStoragePre","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"caller","type":"address"},{"components":[{"internalType":"uint256","name":"balance","type":"uint256"},{"internalType":"bytes32[]","name":"storageKeys","type":"bytes32[]"},{"internalType":"bytes32[]","name":"storageValues","type":"bytes32[]"}],"internalType":"struct NFTVaultSecurityAccount.TracerAccountSolidityLower","name":"pre","type":"tuple"},{"components":[{"internalType":"uint256","name":"balance","type":"uint256"},{"internalType":"bytes32[]","name":"storageKeys","type":"bytes32[]"},{"internalType":"bytes32[]","name":"storageValues","type":"bytes32[]"}],"internalType":"struct NFTVaultSecurityAccount.TracerAccountSolidityLower","name":"post","type":"tuple"},{"components":[{"internalType":"bytes32","name":"eventSigHash","type":"bytes32"},{"internalType":"bytes32[]","name":"parameters","type":"bytes32[]"}],"internalType":"struct NFTVaultSecurityAccount.EventDataLower[]","name":"events","type":"tuple[]"}],"name":"runSecurityChecks","outputs":[],"stateMutability":"nonpayable","type":"function"}]`
// 	parsedABI, err := abi.JSON(strings.NewReader(securityAccountAbi))
// 	if err != nil {
// 		log.Fatalf("Failed to parse ABI: %v", err)
// 	}
// 	// newPre := &vm.TracerAccountSolidity{Balance: pre.Balance}
// 	// Encode the function call
// 	data, err := parsedABI.Pack(default_sec_fn, caller, &pre, &post, &events)

// 	return data, err
// }

func encodeSecuritySmartContractParameterV1(caller common.Address, snapshotAddr common.Address, contractAddr common.Address, events *[]vm.EventData) ([]byte, error) {
	default_sec_fn := "runSecurityChecks"
	// TODO, the abi will be the same as the called smart contract. but function names will change with ips_ at beg. eg: ips_withdraw.
	securityAccountAbi := `[
		{
		  "inputs": [],
		  "stateMutability": "nonpayable",
		  "type": "constructor"
		},
		{
		  "inputs": [
			{
			  "internalType": "address",
			  "name": "caller",
			  "type": "address"
			},
			{
			  "internalType": "address",
			  "name": "snapshotAddr",
			  "type": "address"
			},
			{
			  "internalType": "address",
			  "name": "contractAddr",
			  "type": "address"
			},
			{
			  "components": [
				{
				  "internalType": "bytes32",
				  "name": "eventSigHash",
				  "type": "bytes32"
				},
				{
				  "internalType": "bytes32[]",
				  "name": "parameters",
				  "type": "bytes32[]"
				},				
				{
					"internalType": "address",
					"name": "caller",
					"type": "address"
				  }
			  ],
			  "internalType": "struct TransactionEventsLib.EventData[]",
			  "name": "events",
			  "type": "tuple[]"
			}
		  ],
		  "name": "runSecurityChecks",
		  "outputs": [],
		  "stateMutability": "nonpayable",
		  "type": "function"
		}
	  ]`
	parsedABI, err := abi.JSON(strings.NewReader(securityAccountAbi))
	if err != nil {
		log.Fatalf("Failed to parse ABI: %v", err)
	}
	// newPre := &vm.TracerAccountSolidity{Balance: pre.Balance}
	// Encode the function call
	if events == nil {
		fmt.Println("events is nil")
		events = &[]vm.EventData{}
	}
	// printStruct(*events)

	data, err := parsedABI.Pack(default_sec_fn, caller, snapshotAddr, contractAddr, *events)

	return data, err

}

func (st *StateTransition) refundGas(refundQuotient uint64) {
	st.gasRemaining += st.evm.ProcessingHook.ForceRefundGas()

	nonrefundable := st.evm.ProcessingHook.NonrefundableGas()
	if nonrefundable < st.gasUsed() {
		// Apply refund counter, capped to a refund quotient
		refund := (st.gasUsed() - nonrefundable) / refundQuotient
		if refund > st.state.GetRefund() {
			refund = st.state.GetRefund()
		}
		st.gasRemaining += refund
	}

	// Return ETH for remaining gas, exchanged at the original rate.
	remaining := new(big.Int).Mul(new(big.Int).SetUint64(st.gasRemaining), st.msg.GasPrice)
	st.state.AddBalance(st.msg.From, remaining)

	// Arbitrum: record the gas refund
	if tracer := st.evm.Config.Tracer; tracer != nil {
		tracer.CaptureArbitrumTransfer(st.evm, nil, &st.msg.From, remaining, false, "gasRefund")
	}

	// Also return remaining gas to the block gas counter so it is
	// available for the next transaction.
	st.gp.AddGas(st.gasRemaining)
}

// gasUsed returns the amount of gas used up by the state transition.
func (st *StateTransition) gasUsed() uint64 {
	return st.initialGas - st.gasRemaining
}

// blobGasUsed returns the amount of blob gas used by the message.
func (st *StateTransition) blobGasUsed() uint64 {
	return uint64(len(st.msg.BlobHashes) * params.BlobTxBlobGasPerBlob)
}

func printStruct(struc interface{}) {
	jsonData, _ := json.MarshalIndent(struc, "", "  ")
	fmt.Println("====> events " + string(jsonData))
}

func (m *Message) Debug() {
	fmt.Printf("To: %s\n", m.To.Hex())
	fmt.Printf("From: %s\n", m.From.Hex())
	fmt.Printf("Nonce: %d\n", m.Nonce)
	fmt.Printf("Value: %s\n", m.Value.String())
	fmt.Printf("GasLimit: %d\n", m.GasLimit)
	fmt.Printf("GasPrice: %s\n", m.GasPrice.String())
	fmt.Printf("GasFeeCap: %s\n", m.GasFeeCap.String())
	fmt.Printf("GasTipCap: %s\n", m.GasTipCap.String())
	fmt.Printf("Data: %x\n", m.Data)
	for i, al := range m.AccessList {
		fmt.Printf("AccessList[%d]: Address: %s, StorageKeys: %v\n", i, al.Address.Hex(), al.StorageKeys)
	}
	fmt.Printf("BlobGasFeeCap: %s\n", m.BlobGasFeeCap.String())
	for i, hash := range m.BlobHashes {
		fmt.Printf("BlobHashes[%d]: %s\n", i, hash.Hex())
	}
	fmt.Printf("SkipAccountChecks: %v\n", m.SkipAccountChecks)
}

func DebugPrintMap(accountsMap map[common.Address]*vm.TracerAccount) {
	for address, account := range accountsMap {
		fmt.Printf("Address: %s\n", address.Hex())
		account.DebugPrint()
		fmt.Println("------")
	}
}

func DebugEvents(accountsMap map[common.Address]*vm.TracerAccount) {
	for address, account := range accountsMap {
		fmt.Printf("Address: %s\n", address.Hex())
		account.DebugPrint()
		fmt.Println("------")
	}
}
func DebugPrintArray(accountsMap []vm.TracerAccountSolidity) {
	for _, account := range accountsMap {
		account.DebugPrint()
		fmt.Println("------")
	}
}

// callTrace is the result of a callTracer run.
type CallTrace struct {
	From         common.Address  `json:"from"`
	Gas          *hexutil.Uint64 `json:"gas"`
	GasUsed      *hexutil.Uint64 `json:"gasUsed"`
	To           *common.Address `json:"to,omitempty"`
	Input        hexutil.Bytes   `json:"input"`
	Output       hexutil.Bytes   `json:"output,omitempty"`
	Error        string          `json:"error,omitempty"`
	RevertReason string          `json:"revertReason,omitempty"`
	Calls        []CallTrace     `json:"calls,omitempty"`
	Logs         []CallLog       `json:"logs,omitempty"`
	Value        *hexutil.Big    `json:"value,omitempty"`
	// Gencodec adds overridden fields at the end
	Type string `json:"type"`
}

// callLog is the result of LOG opCode
type CallLog struct {
	Address common.Address `json:"address"`
	Topics  []common.Hash  `json:"topics"`
	Data    hexutil.Bytes  `json:"data"`
}

func getSCRevertReason(revertReason []byte) []byte {
	// Check if byteArray has enough length
	if len(revertReason) < 36 {
		fmt.Println(fmt.Errorf("reason array too short: %d", len(revertReason)))
		panic(1)
	}
	// 1. Get the byte at slot 35
	valueAt35 := revertReason[35]

	// 2. Calculate the new index (35 + value at slot 35)
	newIndex := 35 + int(valueAt35)

	// Check if newArray has enoug	h length for newIndex
	if len(revertReason) <= newIndex {
		fmt.Println(fmt.Errorf("reason array too short: %d", len(revertReason)))
		panic(1)
	}

	// 3. Read the new value and assign it as the size of the message
	messageSize := revertReason[newIndex]

	// Check if byteArray has enough length for the message
	if len(revertReason) < newIndex+1+int(messageSize) {
		fmt.Println(fmt.Errorf("reason array too short: %d", len(revertReason)))
		panic(1)
	}

	// 4. Read the message
	messageStartIndex := newIndex + 1
	revertReasonStr := revertReason[messageStartIndex : messageStartIndex+int(messageSize)]

	return revertReasonStr

}

// as values as stored in 32 bytes, messages can be padded and each 32 bytes secion as to be access differntly.
// as we dont know the size of the message we should iterate over the array.
// remember devs is it good
func getRevertReasonMessage(revertReason []byte, startIndex int, length int) []byte {
	size := startIndex + length
	// Ensure start and length are within bounds.
	if startIndex < 0 || startIndex >= len(revertReason) {
		fmt.Println("Start index out of bounds.")
		return []byte{}
	}
	const chunkSize = 32
	result := make([]byte, 0, length)

	for startIndex < size {
		chunkEnd := startIndex + chunkSize
		if chunkEnd > size {
			chunkEnd = size // Ensure we don't go beyond the available data.
		}
		result = append(result, revertReason[startIndex:chunkEnd]...)

		// Update start to the next chunk's start.
		startIndex = chunkEnd
	}

	return result
}
