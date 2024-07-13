// Copyright 2020 The go-ethereum Authors
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
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/state/snapshot"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/stretchr/testify/assert"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/holiman/uint256"
)

// MyContractRef is a custom implementation of the ContractRef interface
type MyContractRef struct {
	// You can include any additional fields you need here
	address common.Address
}

// Address implements the Address method of the ContractRef interface
func (ref *MyContractRef) Address() common.Address {
	return ref.address
}

// TestStateProcessorErrors tests the output from the 'core' errors
// as defined in core/error.go. These errors are generated when the
// blockchain imports bad blocks, meaning blocks which have valid headers but
// contain invalid transactions
func TestCreateContractSnapshot(t *testing.T) {

	// create account
	vmctx := vm.BlockContext{
		CanTransfer: func(vm.StateDB, common.Address, *big.Int) bool { return true },
		Transfer:    func(vm.StateDB, common.Address, common.Address, *big.Int) {},
	}

	var (
		disk     = rawdb.NewMemoryDatabase()
		tdb      = trie.NewDatabase(disk, nil)
		db       = state.NewDatabaseWithNodeDB(disk, tdb)
		snaps, _ = snapshot.New(snapshot.Config{CacheSize: 10}, disk, tdb, types.EmptyRootHash)
		state, _ = state.New(types.EmptyRootHash, db, snaps)
		src      = common.HexToAddress("0x1")
		vmenv    = vm.NewEVM(vmctx, vm.TxContext{}, state, params.AllEthashProtocolChanges, vm.Config{ExtraEips: []int{2200}})
	)

	// Initialize account and populate storage
	vmenv.StateDB.CreateAccount(src)

	vmenv.StateDB.AddBalance(src, big.NewInt(1))
	code := []byte("randomcode")
	vmenv.StateDB.SetCode(src, code)
	// change state
	for i := 0; i < 10; i++ {

		slot := common.Hash(uint256.NewInt(uint64(i)).Bytes32())
		value := common.Hash(uint256.NewInt(uint64(10 * i)).Bytes32())

		state.SetState(src, slot, value)
	}
	// snapshot the contract
	// doesnt care about new address generation
	// TODO test when errors
	snapAddr := vmenv.CreateContractSnapshot(&MyContractRef{src}, src, 0)

	for i := 0; i < 10; i++ {
		slot := common.Hash(uint256.NewInt(uint64(i)).Bytes32())
		value := common.Hash(uint256.NewInt(uint64(10 * i)).Bytes32())
		assert.Equal(t, vmenv.StateDB.GetState(src, slot), vmenv.ContractSnapshotsDB.GetState(snapAddr, slot))
		assert.Equal(t, value, vmenv.ContractSnapshotsDB.GetState(snapAddr, slot))
	}

	// check code is the same
	assert.Equal(t, vmenv.StateDB.GetCode(src), vmenv.ContractSnapshotsDB.GetCode(snapAddr))

	// check hash is the same
	assert.Equal(t, vmenv.StateDB.GetCodeHash(src), vmenv.ContractSnapshotsDB.GetCodeHash(snapAddr))

}
