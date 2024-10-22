package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"slices"

	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/db/metadb"
	"go.vocdoni.io/dvote/tree/arbo"
	"go.vocdoni.io/dvote/types"
)

func RandomBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

type Results struct {
	Votes  [][]*big.Int  `json:"votes"`
	Weight *types.BigInt `json:"weight"`
}

func (r Results) Bytes() []byte {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(r)
	if err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func main() {
	dir, err := os.MkdirTemp("", "arbosandbox")
	if err != nil {
		panic(err)
	}

	database, err := metadb.New(db.TypePebble, dir)
	if err != nil {
		panic(err)
	}

	tree, err := arbo.NewTree(arbo.Config{
		Database: database, MaxLevels: 256,
		HashFunction: arbo.HashFunctionBlake3,
	})
	if err != nil {
		panic(err)
	}

	processID := RandomBytes(32)
	censusRoot := RandomBytes(32)
	ballotMode := []byte("1234")
	encryptionKey := RandomBytes(32)
	resultsAdd := Results{Votes: [][]*big.Int{
		{big.NewInt(10), big.NewInt(5)},
	}}
	resultsSub := Results{Votes: [][]*big.Int{
		{big.NewInt(2), big.NewInt(0)},
	}}

	if err := tree.Add([]byte{0x00}, processID); err != nil {
		panic(err)
	}
	if err := tree.Add([]byte{0x01}, censusRoot); err != nil {
		panic(err)
	}
	if err := tree.Add([]byte{0x02}, ballotMode); err != nil {
		panic(err)
	}
	if err := tree.Add([]byte{0x03}, encryptionKey); err != nil {
		panic(err)
	}
	if err := tree.Add([]byte{0x04}, resultsAdd.Bytes()); err != nil {
		panic(err)
	}
	if err := tree.Add([]byte{0x05}, resultsSub.Bytes()); err != nil {
		panic(err)
	}

	n := 200
	v := RandomBytes(32)
	fmt.Printf("value=%x\n", v)
	for i := 1; i <= n; i++ {
		k := binary.BigEndian.AppendUint64(nil, uint64(i))
		if i%(n/10) == 0 {
			fmt.Printf("adding leaves... i=%d, k=%x, v=%x\n", i, k, v)
		}
		if err := tree.Add(k, v); err != nil {
			panic(err)
		}
	}
	fmt.Println(tree.Root())

	cvp, err := tree.GenerateCircomVerifierProof(binary.BigEndian.AppendUint64(nil, uint64(n)))
	if err != nil {
		panic(err)
	}

	jCvp, err := json.Marshal(cvp)
	if err != nil {
		panic(err)
	}

	if err := os.WriteFile("merkleproof.json", jCvp, os.ModePerm); err != nil {
		panic(err)
	}
}

func TestMockProof() {
	dir, err := os.MkdirTemp("", "arbosandbox")
	if err != nil {
		panic(err)
	}

	database, err := metadb.New(db.TypePebble, dir)
	if err != nil {
		panic(err)
	}

	tree, err := arbo.NewTree(arbo.Config{
		Database: database, MaxLevels: 2,
		HashFunction: arbo.HashFunctionBlake3,
	})
	if err != nil {
		panic(err)
	}

	testVector := [][]int64{
		{1, 11},
		{2, 22},
		{3, 33},
		{4, 44},
	}
	bLen := 1
	for i := 0; i < len(testVector); i++ {
		k := arbo.BigIntToBytesLE(bLen, big.NewInt(testVector[i][0]))
		v := arbo.BigIntToBytesLE(bLen, big.NewInt(testVector[i][1]))
		fmt.Println("Xxxxxx")

		if err := tree.Add(k, v); err != nil {
			panic(err)
		}
		r, _ := tree.Root()
		fmt.Printf("root: %x\n", r)
	}

	fmt.Println("Xxxxxx")
	// proof of existence (fnc = 0: inclusion, 1: non inclusion)
	k := arbo.BigIntToBytesLE(bLen, big.NewInt(int64(2)))
	cvp, err := tree.GenerateCircomVerifierProof(k)
	if err != nil {
		panic(err)
	}

	jCvp, err := json.Marshal(cvp)
	if err != nil {
		panic(err)
	}

	if err := os.WriteFile("merkleproof.json", jCvp, os.ModePerm); err != nil {
		panic(err)
	}

	for i, s := range cvp.Siblings {
		if slices.Equal(s, []byte{0x00}) {
			cvp.Siblings[i] = make([]byte, arbo.HashFunctionBlake3.Len())
		}
		fmt.Printf("%d: %x\n", i, s)
	}
	packedSiblings, err := arbo.PackSiblings(arbo.HashFunctionBlake3, cvp.Siblings)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%x\n", packedSiblings)
	valid, err := arbo.CheckProof(arbo.HashFunctionBlake3, cvp.Key, cvp.Value, cvp.Root, packedSiblings)
	if err != nil {
		panic(err)
	}
	fmt.Println(valid)

	// test vector checked with a circom circuit (arbo/testvectors/circom)
	if string(jCvp) != `{"fnc":0,"isOld0":"0","key":"2","oldKey":"0","oldValue":`+
		`"0","root":"70755704430752907713939210840915052123828300891577453884536971074`+
		`920848175663","siblings":["47054855318911889373557136875918838200536543882209`+
		`685643760460715596366786245","12732482889881764663402983939065375479614768924`+
		`666945514899507218577689063645"],"value":"22"}` {
		panic("")
	}
	fmt.Println("root", arbo.BytesToBigInt(cvp.Root))
	fmt.Println("key", arbo.BytesToBigInt(cvp.Key))
	fmt.Println("value", arbo.BytesToBigInt(cvp.Value))
	for _, s := range cvp.Siblings {
		fmt.Println("siblings", arbo.BytesToBigInt(s))
	}

	fmt.Println(hex.EncodeToString(jCvp))
	// proof of non-existence (fnc = 0: inclusion, 1: non inclusion)
	k = arbo.BigIntToBytesLE(bLen, big.NewInt(int64(5)))
	cvp, err = tree.GenerateCircomVerifierProof(k)
	if err != nil {
		panic(err)
	}
	jCvp, err = json.Marshal(cvp)
	if err != nil {
		panic(err)
	}

	if err := os.WriteFile("merkleproof_nonexistence.json", jCvp, os.ModePerm); err != nil {
		panic(err)
	}

	// test vector checked with a circom circuit (arbo/testvectors/circom)
	if string(jCvp) != `{"fnc":1,"isOld0":"0","key":"5","oldKey":"1",`+
		`"oldValue":"11","root":"707557044307529077139392108409150521`+
		`23828300891577453884536971074920848175663","siblings":["2705`+
		`656970605685020392445318012245023584064041982131868263190396`+
		`407390419717","181601661288976851603612382347821387506395865`+
		`69589122132480536455214878560647"],"value":"11"}` {
		panic("")
	}
}
