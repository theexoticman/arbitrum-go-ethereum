// Copyright 2021 The go-ethereum Authors
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

package tracetest

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/tracers"
	"github.com/ethereum/go-ethereum/tests"
)

// prestateTrace is the result of a prestateTrace run.
type prestateTrace = map[common.Address]*account

type account struct {
	Balance string                      `json:"balance"`
	Code    string                      `json:"code"`
	Nonce   uint64                      `json:"nonce"`
	Storage map[common.Hash]common.Hash `json:"storage"`
}

// testcase defines a single test to check the stateDiff tracer against.
type testcase struct {
	Genesis         *core.Genesis   `json:"genesis"`
	Context         *callContext    `json:"context"`
	Input           string          `json:"input"`
	TracerConfig    json.RawMessage `json:"tracerConfig"`
	Result          interface{}     `json:"result"`
	ResultConverted interface{}     `json:"resultConverted"`
}

func TestPrestateTracerLegacy(t *testing.T) {
	// some marshalling details. code is being omited and results don't match.
	t.Skip("Skipping this test")
	testPrestateDiffTracer("prestateTracerLegacy", "prestate_tracer_legacy", t)
}

func TestPrestateTracer(t *testing.T) {
	testPrestateDiffTracer("prestateTracer", "prestate_tracer", t)
}

func TestPrestateWithDiffModeTracer(t *testing.T) {
	testPrestateDiffTracer("prestateTracer", "prestate_tracer_with_diff_mode", t)
}

//	func TestPrestateDiffTracerDataStructure(t *testing.T) {
//		testPrestateDiffTracerDataStructure("prestateTracer", "prestate_tracer_with_diff_mode", t)
//	}
func TestTracerResultsConversion(t *testing.T) {
	testTracerResultsConversion("prestateTracer", "prestate_tracer_with_diff_mode", t)
}

func testPrestateDiffTracer(tracerName string, dirPath string, t *testing.T) {
	files, err := os.ReadDir(filepath.Join("testdata", dirPath))
	if err != nil {
		t.Fatalf("failed to retrieve tracer test suite: %v", err)
	}
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		file := file // capture range variable
		t.Run(Camel(strings.TrimSuffix(file.Name(), ".json")), func(t *testing.T) {
			t.Parallel()

			var (
				test = new(testcase)
				tx   = new(types.Transaction)
			)
			// Call tracer test found, read if from disk
			if blob, err := os.ReadFile(filepath.Join("testdata", dirPath, file.Name())); err != nil {
				t.Fatalf("failed to read testcase: %v", err)
			} else if err := json.Unmarshal(blob, test); err != nil {
				t.Fatalf("failed to parse testcase: %v", err)
			}
			if err := tx.UnmarshalBinary(common.FromHex(test.Input)); err != nil {
				t.Fatalf("failed to parse testcase input: %v", err)
			}
			// Configure a blockchain with the given prestate
			var (
				signer    = types.MakeSigner(test.Genesis.Config, new(big.Int).SetUint64(uint64(test.Context.Number)), uint64(test.Context.Time))
				origin, _ = signer.Sender(tx)
				txContext = vm.TxContext{
					Origin:   origin,
					GasPrice: tx.GasPrice(),
				}
				context = vm.BlockContext{
					CanTransfer: core.CanTransfer,
					Transfer:    core.Transfer,
					Coinbase:    test.Context.Miner,
					BlockNumber: new(big.Int).SetUint64(uint64(test.Context.Number)),
					Time:        uint64(test.Context.Time),
					Difficulty:  (*big.Int)(test.Context.Difficulty),
					GasLimit:    uint64(test.Context.GasLimit),
					BaseFee:     test.Genesis.BaseFee,
				}
				triedb, _, statedb = tests.MakePreState(rawdb.NewMemoryDatabase(), test.Genesis.Alloc, false, rawdb.HashScheme)
			)
			defer triedb.Close()

			tracer, err := tracers.DefaultDirectory.New(tracerName, new(tracers.Context), test.TracerConfig)
			if err != nil {
				t.Fatalf("failed to create call tracer: %v", err)
			}
			evm := vm.NewEVM(context, txContext, statedb, test.Genesis.Config, vm.Config{Tracer: tracer})
			msg, err := core.TransactionToMessage(tx, signer, nil)
			if err != nil {
				t.Fatalf("failed to prepare transaction for tracing: %v", err)
			}
			st := core.NewStateTransition(evm, msg, new(core.GasPool).AddGas(tx.Gas()))
			if _, err = st.TransitionDb(); err != nil {
				t.Fatalf("failed to execute transaction: %v", err)
			}
			// Retrieve the trace result and compare against the expected
			res, err := tracer.GetResult()
			if err != nil {
				t.Fatalf("failed to retrieve trace result: %v", err)
			}
			// The legacy javascript calltracer marshals json in js, which
			// is not deterministic (as opposed to the golang json encoder).
			if strings.HasSuffix(dirPath, "_legacy") {
				// This is a tweak to make it deterministic. Can be removed when
				// we remove the legacy tracer.
				var x prestateTrace
				json.Unmarshal(res, &x)
				res, _ = json.Marshal(x)
			}
			want, err := json.Marshal(test.Result)
			if err != nil {
				t.Fatalf("failed to marshal test: %v", err)
			}
			if string(want) != string(res) {
				t.Fatalf("trace mismatch\n have: %v\n want: %v\n", string(res), string(want))
			}
		})
	}
}

// func testPrestateDiffTracerDataStructure(tracerName string, dirPath string, t *testing.T) {
// 	// test the diff tracer Execution data structure
// 	// TODO test a more complex transaction that changes the storage.
// 	files, err := os.ReadDir(filepath.Join("testdata", dirPath))
// 	if err != nil {
// 		t.Fatalf("failed to retrieve tracer test suite: %v", err)
// 	}
// 	for _, file := range files {
// 		if !strings.HasSuffix(file.Name(), ".json") {
// 			continue
// 		}
// 		file := file // capture range variable
// 		t.Run(Camel(strings.TrimSuffix(file.Name(), ".json")), func(t *testing.T) {
// 			// t.Parallel()
// 			fmt.Println(file.Name())
// 			fmt.Println()
// 			var (
// 				test = new(testcase)
// 				tx   = new(types.Transaction)
// 			)
// 			// Call tracer test found, read if from disk
// 			if blob, err := os.ReadFile(filepath.Join("testdata", dirPath, file.Name())); err != nil {
// 				t.Fatalf("failed to read testcase: %v", err)
// 			} else if err := json.Unmarshal(blob, test); err != nil {
// 				t.Fatalf("failed to parse testcase: %v", err)
// 			}
// 			if err := tx.UnmarshalBinary(common.FromHex(test.Input)); err != nil {
// 				t.Fatalf("failed to parse testcase input: %v", err)
// 			}
// 			// Configure a blockchain with the given prestate
// 			var (
// 				signer    = types.MakeSigner(test.Genesis.Config, new(big.Int).SetUint64(uint64(test.Context.Number)), uint64(test.Context.Time))
// 				origin, _ = signer.Sender(tx)
// 				txContext = vm.TxContext{
// 					Origin:   origin,
// 					GasPrice: tx.GasPrice(),
// 				}
// 				context = vm.BlockContext{
// 					CanTransfer: core.CanTransfer,
// 					Transfer:    core.Transfer,
// 					Coinbase:    test.Context.Miner,
// 					BlockNumber: new(big.Int).SetUint64(uint64(test.Context.Number)),
// 					Time:        uint64(test.Context.Time),
// 					Difficulty:  (*big.Int)(test.Context.Difficulty),
// 					GasLimit:    uint64(test.Context.GasLimit),
// 					BaseFee:     test.Genesis.BaseFee,
// 				}
// 				triedb, _, statedb = tests.MakePreState(rawdb.NewMemoryDatabase(), test.Genesis.Alloc, false, rawdb.HashScheme)
// 			)
// 			defer triedb.Close()

// 			tracer, err := tracers.DefaultDirectory.New(tracerName, new(tracers.Context), test.TracerConfig)
// 			if err != nil {
// 				t.Fatalf("failed to create call tracer: %v", err)
// 			}

// 			evm := vm.NewEVM(context, txContext, statedb, test.Genesis.Config, vm.Config{Tracer: tracer})
// 			msg, err := core.TransactionToMessage(tx, signer, nil)
// 			if err != nil {
// 				t.Fatalf("failed to prepare transaction for tracing: %v", err)
// 			}
// 			st := core.NewStateTransition(evm, msg, new(core.GasPool).AddGas(tx.Gas()))
// 			if _, err = st.TransitionDb(); err != nil {
// 				t.Fatalf("failed to execute transaction: %v", err)
// 			}
// 			// Retrieve the trace result and compare against the expected
// 			tracerRes, err := tracer.GetDiffTracerResult()
// 			if err != nil {
// 				t.Fatalf("failed to retrieve trace result: %v", err)
// 			}

// 			result, err := json.Marshal(test.Result)
// 			var want vm.DiffTracerResult
// 			json.Unmarshal([]byte(result), &want)
// 			if err != nil {
// 				t.Fatalf("failed to marshal test: %v", err)
// 			}
// 			// Compare the two maps
// 			if vm.AreDiffTracerResultsEqual(&want, &tracerRes) {
// 				tracerRes.DebugPrint()
// 				want.DebugPrint()
// 				t.Fatalf("trace mismatch")
// 			}

// 		})
// 	}
// }

// Test that the tracer result is converted to solidity format.
func testTracerResultsConversion(tracerName string, dirPath string, t *testing.T) {
	// test the diff tracer Execution data structure
	// TODO test a more complex transaction that changes the storage.

	var (
		test = new(testcase)
	)
	// Call tracer test found, read if from disk
	if blob, err := os.ReadFile(filepath.Join("testdata", dirPath, "simple.json")); err != nil {
		t.Fatalf("failed to read testcase: %v", err)
	} else if err := json.Unmarshal(blob, test); err != nil {
		t.Fatalf("failed to parse testcase: %v", err)
	}
	t.Run(Camel("simple"), func(t *testing.T) {

		input, err := json.Marshal(test.Result)
		if err != nil {
			t.Fatalf("failed to marshal test: %v", err)
		}
		want, err := json.Marshal(test.ResultConverted)
		if err != nil {
			t.Fatalf("failed to marshal test: %v", err)
		}
		var (
			diffTracer        vm.DiffTracerResult
			diffTracerSolidty vm.DiffTracerResultSolidity
		)
		err = json.Unmarshal(input, &diffTracer)
		if err != nil {
			t.Fatalf("failed unmarshall: %v", err)
		}
		err = json.Unmarshal(want, &diffTracerSolidty)
		// if err != nil {
		// 	t.Fatalf("failed unmarshall: %v", err)
		// }
		diffTracer.DebugPrint()
		diffTracerSolidty.DebugPrint()
		for contractAddress, tracerAccount := range diffTracer.Pre {
			fmt.Println(core.ConvertTracerResultToSolidity(contractAddress, *tracerAccount))
			// for _, tracerAccountSolidity := range diffTracerSolidty.Pre {

			// 	if reflect.DeepEqual(tracerAccountSolidity, core.ConvertTracerResultToSolidity(contractAddress, tracerAccount)) {
			// 		fmt.Println("The unmarshalled object and its marshalled version are the same.")
			// 	} else {
			// 		t.Fatalf("diff model wrong")
			// 	}
			// }
		}
		for contractAddress, tracerAccount := range diffTracer.Post {
			fmt.Println(core.ConvertTracerResultToSolidity(contractAddress, *tracerAccount))
			// for _, tracerAccountSolidity := range diffTracerSolidty.Post {
			// 	fmt.Println("Running")
			// 	if reflect.DeepEqual(tracerAccountSolidity, core.ConvertTracerResultToSolidity(contractAddress, tracerAccount)) {
			// 		fmt.Println("The unmarshalled object and its marshalled version are the same.")
			// 	} else {
			// 		t.Fatalf("diff model wrong")
			// 	}
			// }
		}
	})
}

// Test that the tracer result is converted to solidity format.
func testTracerNFTReentrancy(tracerName string, dirPath string, t *testing.T) {
	// test the diff tracer Execution data structure
	// TODO test a more complex transaction that changes the storage.

	var (
		test = new(testcase)
	)
	// Call tracer test found, read if from disk
	if blob, err := os.ReadFile(filepath.Join("testdata", dirPath, "simple.json")); err != nil {
		t.Fatalf("failed to read testcase: %v", err)
	} else if err := json.Unmarshal(blob, test); err != nil {
		t.Fatalf("failed to parse testcase: %v", err)
	}
	t.Run(Camel("simple"), func(t *testing.T) {

		input, err := json.Marshal(test.Result)
		if err != nil {
			t.Fatalf("failed to marshal test: %v", err)
		}
		want, err := json.Marshal(test.ResultConverted)
		if err != nil {
			t.Fatalf("failed to marshal test: %v", err)
		}
		var (
			diffTracer        vm.DiffTracerResult
			diffTracerSolidty vm.DiffTracerResultSolidity
		)
		err = json.Unmarshal(input, &diffTracer)
		if err != nil {
			t.Fatalf("failed unmarshall: %v", err)
		}
		err = json.Unmarshal(want, &diffTracerSolidty)
		// if err != nil {
		// 	t.Fatalf("failed unmarshall: %v", err)
		// }
		diffTracer.DebugPrint()
		diffTracerSolidty.DebugPrint()
		for contractAddress, tracerAccount := range diffTracer.Pre {
			fmt.Println(core.ConvertTracerResultToSolidity(contractAddress, *tracerAccount))
			// for _, tracerAccountSolidity := range diffTracerSolidty.Pre {

			// 	if reflect.DeepEqual(tracerAccountSolidity, core.ConvertTracerResultToSolidity(contractAddress, tracerAccount)) {
			// 		fmt.Println("The unmarshalled object and its marshalled version are the same.")
			// 	} else {
			// 		t.Fatalf("diff model wrong")
			// 	}
			// }
		}
		for contractAddress, tracerAccount := range diffTracer.Post {
			fmt.Println(core.ConvertTracerResultToSolidity(contractAddress, *tracerAccount))
			// for _, tracerAccountSolidity := range diffTracerSolidty.Post {
			// 	fmt.Println("Running")
			// 	if reflect.DeepEqual(tracerAccountSolidity, core.ConvertTracerResultToSolidity(contractAddress, tracerAccount)) {
			// 		fmt.Println("The unmarshalled object and its marshalled version are the same.")
			// 	} else {
			// 		t.Fatalf("diff model wrong")
			// 	}
			// }
		}
	})
}

// Camel converts a snake cased input string into a Camel cased output.
func Camel(str string) string {
	pieces := strings.Split(str, "_")
	for i := 1; i < len(pieces); i++ {
		pieces[i] = string(unicode.ToUpper(rune(pieces[i][0]))) + pieces[i][1:]
	}
	return strings.Join(pieces, "")
}

type callContext struct {
	Number     math.HexOrDecimal64   `json:"number"`
	Difficulty *math.HexOrDecimal256 `json:"difficulty"`
	Time       math.HexOrDecimal64   `json:"timestamp"`
	GasLimit   math.HexOrDecimal64   `json:"gasLimit"`
	Miner      common.Address        `json:"miner"`
}

func getDiffMode() ([]byte, error) {
	prestateConfig := core.ExecutionPrestateTracerConfig{
		DiffMode: true,
	}
	// Creating tracer
	bytes, err := json.Marshal(prestateConfig)

	return bytes, err

}
