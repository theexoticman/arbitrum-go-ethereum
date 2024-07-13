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
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/big"
	"strings"
	"testing"
	"unicode"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/consensus/misc/eip1559"
	"github.com/ethereum/go-ethereum/consensus/misc/eip4844"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/holiman/uint256"
	"golang.org/x/crypto/sha3"
)

func u64(val uint64) *uint64 { return &val }

// TestStateProcessorErrors tests the output from the 'core' errors
// as defined in core/error.go. These errors are generated when the
// blockchain imports bad blocks, meaning blocks which have valid headers but
// contain invalid transactions
func TestStateProcessorErrors(t *testing.T) {
	var (
		config = &params.ChainConfig{
			ChainID:                       big.NewInt(1),
			HomesteadBlock:                big.NewInt(0),
			EIP150Block:                   big.NewInt(0),
			EIP155Block:                   big.NewInt(0),
			EIP158Block:                   big.NewInt(0),
			ByzantiumBlock:                big.NewInt(0),
			ConstantinopleBlock:           big.NewInt(0),
			PetersburgBlock:               big.NewInt(0),
			IstanbulBlock:                 big.NewInt(0),
			MuirGlacierBlock:              big.NewInt(0),
			BerlinBlock:                   big.NewInt(0),
			LondonBlock:                   big.NewInt(0),
			Ethash:                        new(params.EthashConfig),
			TerminalTotalDifficulty:       big.NewInt(0),
			TerminalTotalDifficultyPassed: true,
			ShanghaiTime:                  new(uint64),
			CancunTime:                    new(uint64),
		}
		signer  = types.LatestSigner(config)
		key1, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		key2, _ = crypto.HexToECDSA("0202020202020202020202020202020202020202020202020202002020202020")
	)
	var makeTx = func(key *ecdsa.PrivateKey, nonce uint64, to common.Address, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte) *types.Transaction {
		tx, _ := types.SignTx(types.NewTransaction(nonce, to, amount, gasLimit, gasPrice, data), signer, key)
		return tx
	}
	var mkDynamicTx = func(nonce uint64, to common.Address, gasLimit uint64, gasTipCap, gasFeeCap *big.Int) *types.Transaction {
		tx, _ := types.SignTx(types.NewTx(&types.DynamicFeeTx{
			Nonce:     nonce,
			GasTipCap: gasTipCap,
			GasFeeCap: gasFeeCap,
			Gas:       gasLimit,
			To:        &to,
			Value:     big.NewInt(0),
		}), signer, key1)
		return tx
	}
	var mkDynamicCreationTx = func(nonce uint64, gasLimit uint64, gasTipCap, gasFeeCap *big.Int, data []byte) *types.Transaction {
		tx, _ := types.SignTx(types.NewTx(&types.DynamicFeeTx{
			Nonce:     nonce,
			GasTipCap: gasTipCap,
			GasFeeCap: gasFeeCap,
			Gas:       gasLimit,
			Value:     big.NewInt(0),
			Data:      data,
		}), signer, key1)
		return tx
	}
	var mkBlobTx = func(nonce uint64, to common.Address, gasLimit uint64, gasTipCap, gasFeeCap *big.Int, hashes []common.Hash) *types.Transaction {
		tx, err := types.SignTx(types.NewTx(&types.BlobTx{
			Nonce:      nonce,
			GasTipCap:  uint256.MustFromBig(gasTipCap),
			GasFeeCap:  uint256.MustFromBig(gasFeeCap),
			Gas:        gasLimit,
			To:         to,
			BlobHashes: hashes,
			Value:      new(uint256.Int),
		}), signer, key1)
		if err != nil {
			t.Fatal(err)
		}
		return tx
	}

	{ // Tests against a 'recent' chain definition
		var (
			db    = rawdb.NewMemoryDatabase()
			gspec = &Genesis{
				Config: config,
				Alloc: GenesisAlloc{
					common.HexToAddress("0x71562b71999873DB5b286dF957af199Ec94617F7"): GenesisAccount{
						Balance: big.NewInt(1000000000000000000), // 1 ether
						Nonce:   0,
					},
					common.HexToAddress("0xfd0810DD14796680f72adf1a371963d0745BCc64"): GenesisAccount{
						Balance: big.NewInt(1000000000000000000), // 1 ether
						Nonce:   math.MaxUint64,
					},
				},
			}
			blockchain, _  = NewBlockChain(db, nil, nil, gspec, nil, beacon.New(ethash.NewFaker()), vm.Config{}, nil, nil)
			tooBigInitCode = [params.DefaultMaxInitCodeSize + 1]byte{}
		)

		defer blockchain.Stop()
		bigNumber := new(big.Int).SetBytes(common.FromHex("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"))
		tooBigNumber := new(big.Int).Set(bigNumber)
		tooBigNumber.Add(tooBigNumber, common.Big1)
		for i, tt := range []struct {
			txs  []*types.Transaction
			want string
		}{
			{ // ErrNonceTooLow
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, big.NewInt(0), params.TxGas, big.NewInt(875000000), nil),
					makeTx(key1, 0, common.Address{}, big.NewInt(0), params.TxGas, big.NewInt(875000000), nil),
				},
				want: "could not apply tx 1 [0x0026256b3939ed97e2c4a6f3fce8ecf83bdcfa6d507c47838c308a1fb0436f62]: nonce too low: address 0x71562b71999873DB5b286dF957af199Ec94617F7, tx: 0 state: 1",
			},
			{ // ErrNonceTooHigh
				txs: []*types.Transaction{
					makeTx(key1, 100, common.Address{}, big.NewInt(0), params.TxGas, big.NewInt(875000000), nil),
				},
				want: "could not apply tx 0 [0xdebad714ca7f363bd0d8121c4518ad48fa469ca81b0a081be3d10c17460f751b]: nonce too high: address 0x71562b71999873DB5b286dF957af199Ec94617F7, tx: 100 state: 0",
			},
			{ // ErrNonceMax
				txs: []*types.Transaction{
					makeTx(key2, math.MaxUint64, common.Address{}, big.NewInt(0), params.TxGas, big.NewInt(875000000), nil),
				},
				want: "could not apply tx 0 [0x84ea18d60eb2bb3b040e3add0eb72f757727122cc257dd858c67cb6591a85986]: nonce has max value: address 0xfd0810DD14796680f72adf1a371963d0745BCc64, nonce: 18446744073709551615",
			},
			{ // ErrGasLimitReached
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, big.NewInt(0), 21000000, big.NewInt(875000000), nil),
				},
				want: "could not apply tx 0 [0xbd49d8dadfd47fb846986695f7d4da3f7b2c48c8da82dbc211a26eb124883de9]: gas limit reached",
			},
			{ // ErrInsufficientFundsForTransfer
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, big.NewInt(1000000000000000000), params.TxGas, big.NewInt(875000000), nil),
				},
				want: "could not apply tx 0 [0x98c796b470f7fcab40aaef5c965a602b0238e1034cce6fb73823042dd0638d74]: insufficient funds for gas * price + value: address 0x71562b71999873DB5b286dF957af199Ec94617F7 have 1000000000000000000 want 1000018375000000000",
			},
			{ // ErrInsufficientFunds
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, big.NewInt(0), params.TxGas, big.NewInt(900000000000000000), nil),
				},
				want: "could not apply tx 0 [0x4a69690c4b0cd85e64d0d9ea06302455b01e10a83db964d60281739752003440]: insufficient funds for gas * price + value: address 0x71562b71999873DB5b286dF957af199Ec94617F7 have 1000000000000000000 want 18900000000000000000000",
			},
			// ErrGasUintOverflow
			// One missing 'core' error is ErrGasUintOverflow: "gas uint64 overflow",
			// In order to trigger that one, we'd have to allocate a _huge_ chunk of data, such that the
			// multiplication len(data) +gas_per_byte overflows uint64. Not testable at the moment
			{ // ErrIntrinsicGas
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, big.NewInt(0), params.TxGas-1000, big.NewInt(875000000), nil),
				},
				want: "could not apply tx 0 [0xcf3b049a0b516cb4f9274b3e2a264359e2ba53b2fb64b7bda2c634d5c9d01fca]: intrinsic gas too low: have 20000, want 21000",
			},
			{ // ErrGasLimitReached
				txs: []*types.Transaction{
					makeTx(key1, 0, common.Address{}, big.NewInt(0), params.TxGas*1000, big.NewInt(875000000), nil),
				},
				want: "could not apply tx 0 [0xbd49d8dadfd47fb846986695f7d4da3f7b2c48c8da82dbc211a26eb124883de9]: gas limit reached",
			},
			{ // ErrFeeCapTooLow
				txs: []*types.Transaction{
					mkDynamicTx(0, common.Address{}, params.TxGas, big.NewInt(0), big.NewInt(0)),
				},
				want: "could not apply tx 0 [0xc4ab868fef0c82ae0387b742aee87907f2d0fc528fc6ea0a021459fb0fc4a4a8]: max fee per gas less than block base fee: address 0x71562b71999873DB5b286dF957af199Ec94617F7, maxFeePerGas: 0 baseFee: 875000000",
			},
			{ // ErrTipVeryHigh
				txs: []*types.Transaction{
					mkDynamicTx(0, common.Address{}, params.TxGas, tooBigNumber, big.NewInt(1)),
				},
				want: "could not apply tx 0 [0x15b8391b9981f266b32f3ab7da564bbeb3d6c21628364ea9b32a21139f89f712]: max priority fee per gas higher than 2^256-1: address 0x71562b71999873DB5b286dF957af199Ec94617F7, maxPriorityFeePerGas bit length: 257",
			},
			{ // ErrFeeCapVeryHigh
				txs: []*types.Transaction{
					mkDynamicTx(0, common.Address{}, params.TxGas, big.NewInt(1), tooBigNumber),
				},
				want: "could not apply tx 0 [0x48bc299b83fdb345c57478f239e89814bb3063eb4e4b49f3b6057a69255c16bd]: max fee per gas higher than 2^256-1: address 0x71562b71999873DB5b286dF957af199Ec94617F7, maxFeePerGas bit length: 257",
			},
			{ // ErrTipAboveFeeCap
				txs: []*types.Transaction{
					mkDynamicTx(0, common.Address{}, params.TxGas, big.NewInt(2), big.NewInt(1)),
				},
				want: "could not apply tx 0 [0xf987a31ff0c71895780a7612f965a0c8b056deb54e020bb44fa478092f14c9b4]: max priority fee per gas higher than max fee per gas: address 0x71562b71999873DB5b286dF957af199Ec94617F7, maxPriorityFeePerGas: 2, maxFeePerGas: 1",
			},
			{ // ErrInsufficientFunds
				// Available balance:           1000000000000000000
				// Effective cost:                   18375000021000
				// FeeCap * gas:                1050000000000000000
				// This test is designed to have the effective cost be covered by the balance, but
				// the extended requirement on FeeCap*gas < balance to fail
				txs: []*types.Transaction{
					mkDynamicTx(0, common.Address{}, params.TxGas, big.NewInt(1), big.NewInt(50000000000000)),
				},
				want: "could not apply tx 0 [0x413603cd096a87f41b1660d3ed3e27d62e1da78eac138961c0a1314ed43bd129]: insufficient funds for gas * price + value: address 0x71562b71999873DB5b286dF957af199Ec94617F7 have 1000000000000000000 want 1050000000000000000",
			},
			{ // Another ErrInsufficientFunds, this one to ensure that feecap/tip of max u256 is allowed
				txs: []*types.Transaction{
					mkDynamicTx(0, common.Address{}, params.TxGas, bigNumber, bigNumber),
				},
				want: "could not apply tx 0 [0xd82a0c2519acfeac9a948258c47e784acd20651d9d80f9a1c67b4137651c3a24]: insufficient funds for gas * price + value: address 0x71562b71999873DB5b286dF957af199Ec94617F7 have 1000000000000000000 want 2431633873983640103894990685182446064918669677978451844828609264166175722438635000",
			},
			{ // ErrMaxInitCodeSizeExceeded
				txs: []*types.Transaction{
					mkDynamicCreationTx(0, 500000, common.Big0, big.NewInt(params.InitialBaseFee), tooBigInitCode[:]),
				},
				want: "could not apply tx 0 [0xd491405f06c92d118dd3208376fcee18a57c54bc52063ee4a26b1cf296857c25]: max initcode size exceeded: code size 49153 limit 49152",
			},
			{ // ErrIntrinsicGas: Not enough gas to cover init code
				txs: []*types.Transaction{
					mkDynamicCreationTx(0, 54299, common.Big0, big.NewInt(params.InitialBaseFee), make([]byte, 320)),
				},
				want: "could not apply tx 0 [0xfd49536a9b323769d8472fcb3ebb3689b707a349379baee3e2ee3fe7baae06a1]: intrinsic gas too low: have 54299, want 54300",
			},
			{ // ErrBlobFeeCapTooLow
				txs: []*types.Transaction{
					mkBlobTx(0, common.Address{}, params.TxGas, big.NewInt(1), big.NewInt(1), []common.Hash{(common.Hash{1})}),
				},
				want: "could not apply tx 0 [0x6c11015985ce82db691d7b2d017acda296db88b811c3c60dc71449c76256c716]: max fee per gas less than block base fee: address 0x71562b71999873DB5b286dF957af199Ec94617F7, maxFeePerGas: 1 baseFee: 875000000",
			},
		} {
			block := GenerateBadBlock(gspec.ToBlock(), beacon.New(ethash.NewFaker()), tt.txs, gspec.Config)
			_, err := blockchain.InsertChain(types.Blocks{block})
			if err == nil {
				t.Fatal("block imported without errors")
			}
			if have, want := err.Error(), tt.want; have != want {
				t.Errorf("test %d:\nhave \"%v\"\nwant \"%v\"\n", i, have, want)
			}
		}
	}

	// ErrTxTypeNotSupported, For this, we need an older chain
	{
		var (
			db    = rawdb.NewMemoryDatabase()
			gspec = &Genesis{
				Config: &params.ChainConfig{
					ChainID:             big.NewInt(1),
					HomesteadBlock:      big.NewInt(0),
					EIP150Block:         big.NewInt(0),
					EIP155Block:         big.NewInt(0),
					EIP158Block:         big.NewInt(0),
					ByzantiumBlock:      big.NewInt(0),
					ConstantinopleBlock: big.NewInt(0),
					PetersburgBlock:     big.NewInt(0),
					IstanbulBlock:       big.NewInt(0),
					MuirGlacierBlock:    big.NewInt(0),
				},
				Alloc: GenesisAlloc{
					common.HexToAddress("0x71562b71999873DB5b286dF957af199Ec94617F7"): GenesisAccount{
						Balance: big.NewInt(1000000000000000000), // 1 ether
						Nonce:   0,
					},
				},
			}
			blockchain, _ = NewBlockChain(db, nil, nil, gspec, nil, ethash.NewFaker(), vm.Config{}, nil, nil)
		)
		defer blockchain.Stop()
		for i, tt := range []struct {
			txs  []*types.Transaction
			want string
		}{
			{ // ErrTxTypeNotSupported
				txs: []*types.Transaction{
					mkDynamicTx(0, common.Address{}, params.TxGas-1000, big.NewInt(0), big.NewInt(0)),
				},
				want: "could not apply tx 0 [0x88626ac0d53cb65308f2416103c62bb1f18b805573d4f96a3640bbbfff13c14f]: transaction type not supported",
			},
		} {
			block := GenerateBadBlock(gspec.ToBlock(), ethash.NewFaker(), tt.txs, gspec.Config)
			_, err := blockchain.InsertChain(types.Blocks{block})
			if err == nil {
				t.Fatal("block imported without errors")
			}
			if have, want := err.Error(), tt.want; have != want {
				t.Errorf("test %d:\nhave \"%v\"\nwant \"%v\"\n", i, have, want)
			}
		}
	}

	// ErrSenderNoEOA, for this we need the sender to have contract code
	{
		var (
			db    = rawdb.NewMemoryDatabase()
			gspec = &Genesis{
				Config: config,
				Alloc: GenesisAlloc{
					common.HexToAddress("0x71562b71999873DB5b286dF957af199Ec94617F7"): GenesisAccount{
						Balance: big.NewInt(1000000000000000000), // 1 ether
						Nonce:   0,
						Code:    common.FromHex("0xB0B0FACE"),
					},
				},
			}
			blockchain, _ = NewBlockChain(db, nil, nil, gspec, nil, beacon.New(ethash.NewFaker()), vm.Config{}, nil, nil)
		)
		defer blockchain.Stop()
		for i, tt := range []struct {
			txs  []*types.Transaction
			want string
		}{
			{ // ErrSenderNoEOA
				txs: []*types.Transaction{
					mkDynamicTx(0, common.Address{}, params.TxGas-1000, big.NewInt(0), big.NewInt(0)),
				},
				want: "could not apply tx 0 [0x88626ac0d53cb65308f2416103c62bb1f18b805573d4f96a3640bbbfff13c14f]: sender not an eoa: address 0x71562b71999873DB5b286dF957af199Ec94617F7, codehash: 0x9280914443471259d4570a8661015ae4a5b80186dbc619658fb494bebc3da3d1",
			},
		} {
			block := GenerateBadBlock(gspec.ToBlock(), beacon.New(ethash.NewFaker()), tt.txs, gspec.Config)
			_, err := blockchain.InsertChain(types.Blocks{block})
			if err == nil {
				t.Fatal("block imported without errors")
			}
			if have, want := err.Error(), tt.want; have != want {
				t.Errorf("test %d:\nhave \"%v\"\nwant \"%v\"\n", i, have, want)
			}
		}
	}
}

// GenerateBadBlock constructs a "block" which contains the transactions. The transactions are not expected to be
// valid, and no proper post-state can be made. But from the perspective of the blockchain, the block is sufficiently
// valid to be considered for import:
// - valid pow (fake), ancestry, difficulty, gaslimit etc
func GenerateBadBlock(parent *types.Block, engine consensus.Engine, txs types.Transactions, config *params.ChainConfig) *types.Block {
	difficulty := big.NewInt(0)
	if !config.TerminalTotalDifficultyPassed {
		difficulty = engine.CalcDifficulty(&fakeChainReader{config}, parent.Time()+10, &types.Header{
			Number:     parent.Number(),
			Time:       parent.Time(),
			Difficulty: parent.Difficulty(),
			UncleHash:  parent.UncleHash(),
		})
	}

	header := &types.Header{
		ParentHash: parent.Hash(),
		Coinbase:   parent.Coinbase(),
		Difficulty: difficulty,
		GasLimit:   parent.GasLimit(),
		Number:     new(big.Int).Add(parent.Number(), common.Big1),
		Time:       parent.Time() + 10,
		UncleHash:  types.EmptyUncleHash,
	}
	if config.IsLondon(header.Number) {
		header.BaseFee = eip1559.CalcBaseFee(config, parent.Header())
	}
	arbosVersion := types.DeserializeHeaderExtraInformation(header).ArbOSFormatVersion
	if config.IsShanghai(header.Number, header.Time, arbosVersion) {
		header.WithdrawalsHash = &types.EmptyWithdrawalsHash
	}
	var receipts []*types.Receipt
	// The post-state result doesn't need to be correct (this is a bad block), but we do need something there
	// Preferably something unique. So let's use a combo of blocknum + txhash
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write(header.Number.Bytes())
	var cumulativeGas uint64
	var nBlobs int
	for _, tx := range txs {
		txh := tx.Hash()
		hasher.Write(txh[:])
		receipt := types.NewReceipt(nil, false, cumulativeGas+tx.Gas())
		receipt.TxHash = tx.Hash()
		receipt.GasUsed = tx.Gas()
		receipts = append(receipts, receipt)
		cumulativeGas += tx.Gas()
		nBlobs += len(tx.BlobHashes())
	}
	header.Root = common.BytesToHash(hasher.Sum(nil))
	if config.IsCancun(header.Number, header.Time, arbosVersion) {
		var pExcess, pUsed = uint64(0), uint64(0)
		if parent.ExcessBlobGas() != nil {
			pExcess = *parent.ExcessBlobGas()
			pUsed = *parent.BlobGasUsed()
		}
		excess := eip4844.CalcExcessBlobGas(pExcess, pUsed)
		used := uint64(nBlobs * params.BlobTxBlobGasPerBlob)
		header.ExcessBlobGas = &excess
		header.BlobGasUsed = &used

		beaconRoot := common.HexToHash("0xbeac00")
		header.ParentBeaconRoot = &beaconRoot
	}
	// Assemble and return the final block for sealing
	if config.IsShanghai(header.Number, header.Time, types.DeserializeHeaderExtraInformation(header).ArbOSFormatVersion) {
		return types.NewBlockWithWithdrawals(header, txs, nil, receipts, []*types.Withdrawal{}, trie.NewStackTrie(nil))
	}
	return types.NewBlock(header, txs, nil, receipts, trie.NewStackTrie(nil))
}

func TestSecurityTestExecution(t *testing.T) {
	t.Skip("Skipping this test for now")
	var (
		config = params.IPSChainConfig
		signer = types.LatestSigner(config)
		ether  = math.BigPow(10, 18)
		bigInt = new(big.Int)

		gspec = &Genesis{
			Config: config,
			Alloc: GenesisAlloc{
				common.HexToAddress("0x71562b71999873DB5b286dF957af199Ec94617F7"): GenesisAccount{
					Balance: bigInt.Mul(big.NewInt(200), ether), // 200 ether
					Nonce:   0,
				},
				common.HexToAddress("0xfd0810DD14796680f72adf1a371963d0745BCc64"): GenesisAccount{
					Balance: bigInt.Mul(big.NewInt(200), ether), // 200 ether
					Nonce:   math.MaxUint64,
				},
			},
		}

		// Vulnerable Vault Byte Code
		vulnerableVaultBytecode, _ = hex.DecodeString("0x608060405234801561001057600080fd5b506105f5806100206000396000f3fe60806040526004361061003f5760003560e01c806327e235e3146100445780632e1a7d4d146100815780636f9fb98a146100aa578063d0e30db0146100d5575b600080fd5b34801561005057600080fd5b5061006b6004803603810190610066919061033f565b6100df565b6040516100789190610385565b60405180910390f35b34801561008d57600080fd5b506100a860048036038101906100a391906103cc565b6100f7565b005b3480156100b657600080fd5b506100bf61027d565b6040516100cc9190610385565b60405180910390f35b6100dd610285565b005b60006020528060005260406000206000915090505481565b806000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020541015610178576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161016f90610456565b60405180910390fd5b60003373ffffffffffffffffffffffffffffffffffffffff168260405161019e906104a7565b60006040518083038185875af1925050503d80600081146101db576040519150601f19603f3d011682016040523d82523d6000602084013e6101e0565b606091505b5050905080610224576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161021b90610508565b60405180910390fd5b816000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282546102729190610557565b925050819055505050565b600047905090565b346000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282546102d3919061058b565b92505081905550565b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b600061030c826102e1565b9050919050565b61031c81610301565b811461032757600080fd5b50565b60008135905061033981610313565b92915050565b600060208284031215610355576103546102dc565b5b60006103638482850161032a565b91505092915050565b6000819050919050565b61037f8161036c565b82525050565b600060208201905061039a6000830184610376565b92915050565b6103a98161036c565b81146103b457600080fd5b50565b6000813590506103c6816103a0565b92915050565b6000602082840312156103e2576103e16102dc565b5b60006103f0848285016103b7565b91505092915050565b600082825260208201905092915050565b7f496e73756666696369656e742062616c616e6365000000000000000000000000600082015250565b60006104406014836103f9565b915061044b8261040a565b602082019050919050565b6000602082019050818103600083015261046f81610433565b9050919050565b600081905092915050565b50565b6000610491600083610476565b915061049c82610481565b600082019050919050565b60006104b282610484565b9150819050919050565b7f5472616e73666572206661696c65640000000000000000000000000000000000600082015250565b60006104f2600f836103f9565b91506104fd826104bc565b602082019050919050565b60006020820190508181036000830152610521816104e5565b9050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b60006105628261036c565b915061056d8361036c565b925082820390508181111561058557610584610528565b5b92915050565b60006105968261036c565b91506105a18361036c565b92508282019050808211156105b9576105b8610528565b5b9291505056fea26469706673582212209b2d32173531d54566955e7d6379fc784e9b7fc1918a8fc6ed66577f36fc35bd64736f6c63430008130033")
		vaultExploiterBytecode, _  = hex.DecodeString("0x608060405234801561001057600080fd5b506040516109663803806109668339818101604052810190610032919061011c565b806000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555033600160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050610149565b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b60006100e9826100be565b9050919050565b6100f9816100de565b811461010457600080fd5b50565b600081519050610116816100f0565b92915050565b600060208284031215610132576101316100b9565b5b600061014084828501610107565b91505092915050565b61080e806101586000396000f3fe6080604052600436106100435760003560e01c806324600fc31461012657806383aca9cd1461013d5780638da5cb5b146101685780639e5faafc146101935761004a565b3661004a57005b670de0b6b3a764000060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1631106101245760008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16632e1a7d4d670de0b6b3a76400006040518263ffffffff1660e01b81526004016100f1919061052a565b600060405180830381600087803b15801561010b57600080fd5b505af115801561011f573d6000803e3d6000fd5b505050505b005b34801561013257600080fd5b5061013b61019d565b005b34801561014957600080fd5b50610152610298565b60405161015f91906105ba565b60405180910390f35b34801561017457600080fd5b5061017d6102bc565b60405161018a91906105f6565b60405180910390f35b61019b6102e2565b005b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff161461022d576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161022490610694565b60405180910390fd5b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff166108fc479081150290604051600060405180830381858888f19350505050158015610295573d6000803e3d6000fd5b50565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b600160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614610372576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161036990610726565b60405180910390fd5b670de0b6b3a76400003410156103bd576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016103b4906107b8565b60405180910390fd5b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1663d0e30db0670de0b6b3a76400006040518263ffffffff1660e01b81526004016000604051808303818588803b15801561042d57600080fd5b505af1158015610441573d6000803e3d6000fd5b505050505060008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16632e1a7d4d670de0b6b3a76400006040518263ffffffff1660e01b81526004016104a7919061052a565b600060405180830381600087803b1580156104c157600080fd5b505af11580156104d5573d6000803e3d6000fd5b50505050565b6000819050919050565b6000819050919050565b6000819050919050565b600061051461050f61050a846104db565b6104ef565b6104e5565b9050919050565b610524816104f9565b82525050565b600060208201905061053f600083018461051b565b92915050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b600061058061057b61057684610545565b6104ef565b610545565b9050919050565b600061059282610565565b9050919050565b60006105a482610587565b9050919050565b6105b481610599565b82525050565b60006020820190506105cf60008301846105ab565b92915050565b60006105e082610545565b9050919050565b6105f0816105d5565b82525050565b600060208201905061060b60008301846105e7565b92915050565b600082825260208201905092915050565b7f4f6e6c7920746865206f776e65722063616e2077697468647261772066756e6460008201527f7300000000000000000000000000000000000000000000000000000000000000602082015250565b600061067e602183610611565b915061068982610622565b604082019050919050565b600060208201905081810360008301526106ad81610671565b9050919050565b7f4f6e6c7920746865206f776e65722063616e20696e697469617465207468652060008201527f61747461636b0000000000000000000000000000000000000000000000000000602082015250565b6000610710602683610611565b915061071b826106b4565b604082019050919050565b6000602082019050818103600083015261073f81610703565b9050919050565b7f53656e64206174206c65617374203120657468657220746f207374617274207460008201527f68652061747461636b0000000000000000000000000000000000000000000000602082015250565b60006107a2602983610611565b91506107ad82610746565b604082019050919050565b600060208201905081810360008301526107d181610795565b905091905056fea2646970667358221220a894e18f1c4ea5fc723b992e8e22c8e1aba953e8833baba9b2e79990c4e136ee64736f6c63430008130033")
		//abis
		vulnerableVaultAbi = `[{"inputs":[{"internalType":"address","name":"","type":"address"}],"name":"balances","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"deposit","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[],"name":"getContractBalance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"withdraw","outputs":[],"stateMutability":"nonpayable","type":"function"}]`
		exploiterAbi       = `[{"inputs":[{"internalType":"address","name":"_vulnerableVault","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"stateMutability":"payable","type":"fallback"},{"inputs":[],"name":"attack","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"vulnerableVault","outputs":[{"internalType":"contract IVulnerableVault","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"withdrawFunds","outputs":[],"stateMutability":"nonpayable","type":"function"},{"stateMutability":"payable","type":"receive"}]`
		// Create two test users
		projectKeys, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		hackerKeys, _  = crypto.HexToECDSA("0202020202020202020202020202020202020202020202020202002020202020")

		data, _         = buildTxInput(vulnerableVaultAbi, "deposit", nil)
		exploitInput, _ = buildTxInput(exploiterAbi, "attack", nil)

		emptyAddress common.Address
		gas          uint64 = 100_000
	)

	var makeTx = func(key *ecdsa.PrivateKey, nonce uint64, to common.Address, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte) *types.Transaction {
		tx, _ := types.SignTx(types.NewTransaction(nonce, to, amount, gasLimit, gasPrice, data), signer, key)
		return tx
	}

	// key1 deposit amount in the vault.
	// key2 deposit amount in the vault.]
	// for _, tt := range []struct {
	// 	txs []*types.Transaction
	// }{
	// 	{txs: []*types.Transaction{deployVaultTx, send100VaultTx, deployMaliciousTx, exploitTx}},
	// } {
	//db, blocks, receipts
	_, _, _ = GenerateChainWithGenesis(gspec, ethash.NewFaker(), 1024, func(i int, block *BlockGen) {

		// Deploy vulnerable vault
		deployVaultTx, _ := CreateContract(projectKeys, 0, signer, vulnerableVaultBytecode)
		// deployVaultTx := makeTx(projectKeys, 0, emptyAddress, big.NewInt(0), params.TxGas, big.NewInt(875000000), vulnerableVaultBytecode)
		block.AddTx(deployVaultTx)
		deployedAddress := block.receipts[len(block.receipts)-1].ContractAddress
		// project sends 10 ethers to vault

		eth100 := bigInt.Mul(big.NewInt(100), ether)

		send100VaultTx := makeTx(projectKeys, 1, deployedAddress, eth100, gas, big.NewInt(875000000), data)
		block.AddTx(send100VaultTx)

		// Deploy malicious smart contract
		deployMaliciousTx, _ := CreateContract(hackerKeys, 0, signer, vaultExploiterBytecode)
		block.AddTx(deployMaliciousTx)

		// Exploit in malicious smart contract
		eth2 := bigInt.Mul(big.NewInt(2), ether)

		exploitTx := makeTx(hackerKeys, 1, emptyAddress, eth2, gas, big.NewInt(875000000), exploitInput)
		block.AddTx(exploitTx)

	})
	// bc:=ethapi.NewChainContext(&ethapi.ChainContextBackend{}, backend)
	// block := GenerateBadBlock(gspec.ToBlock(), beacon.New(ethash.NewFaker()), tt.txs, config)
	// ApplyTransaction(params.IPSChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config)
	// _, err := blockchain.InsertChain(types.Blocks{block})
	// if err == nil {
	// 	t.Fatal("block imported without errors")
	// }

}

func CreateContract(key *ecdsa.PrivateKey, nonce uint64, signer types.Signer, data []byte) (*types.Transaction, error) {
	txdata := &types.LegacyTx{
		Nonce:    nonce,
		Gas:      80000,
		GasPrice: big.NewInt(875000000),
		Data:     data,
	}
	tx, err := types.SignNewTx(key, signer, txdata)
	return tx, err

}

func buildTxInput(contractAbi string, function_name string, params ...interface{}) ([]byte, error) {
	contractAbiBytes, err := abi.JSON(strings.NewReader(contractAbi))
	if err != nil {
		log.Fatalf("Failed to parse ABI: %v", err)
	}

	var (
		data []byte
	)
	// Encode the function call
	if len(params) == 1 && params[0] == nil {
		data, err = contractAbiBytes.Pack(function_name)
	} else {
		data, err = contractAbiBytes.Pack(function_name, params)
	}
	return data, err
}

// Camel converts a snake cased input string into a Camel cased output.
func Camel(str string) string {
	pieces := strings.Split(str, "_")
	for i := 1; i < len(pieces); i++ {
		pieces[i] = string(unicode.ToUpper(rune(pieces[i][0]))) + pieces[i][1:]
	}
	return strings.Join(pieces, "")
}

// testcase defines a single test to check the stateDiff tracer against.
type testcase struct {
	Genesis      *Genesis        `json:"genesis"`
	Context      *callContext    `json:"context"`
	Input        string          `json:"input"`
	TracerConfig json.RawMessage `json:"tracerConfig"`
	Result       interface{}     `json:"result"`
}

type callContext struct {
	Number     math.HexOrDecimal64   `json:"number"`
	Difficulty *math.HexOrDecimal256 `json:"difficulty"`
	Time       math.HexOrDecimal64   `json:"timestamp"`
	GasLimit   math.HexOrDecimal64   `json:"gasLimit"`
	Miner      common.Address        `json:"miner"`
}
