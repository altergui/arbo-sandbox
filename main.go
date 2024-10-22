package main

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

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

	keyLen := 32
	maxLevels := keyLen * 8
	tree, err := arbo.NewTree(arbo.Config{
		Database: database, MaxLevels: maxLevels,
		HashFunction: arbo.HashFunctionBlake3,
	})
	if err != nil {
		panic(err)
	}

	processID := RandomBytes(keyLen)
	censusRoot := RandomBytes(keyLen)
	ballotMode := []byte("1234")
	encryptionKey := RandomBytes(keyLen)
	resultsAdd := Results{Votes: [][]*big.Int{
		{big.NewInt(10), big.NewInt(5)},
	}}
	resultsSub := Results{Votes: [][]*big.Int{
		{big.NewInt(2), big.NewInt(0)},
	}}

	if err := tree.Add(arbo.BigIntToBytesLE(keyLen, big.NewInt(0x00)), processID); err != nil {
		panic(err)
	}
	if err := tree.Add(arbo.BigIntToBytesLE(keyLen, big.NewInt(0x01)), censusRoot); err != nil {
		panic(err)
	}
	if err := tree.Add(arbo.BigIntToBytesLE(keyLen, big.NewInt(0x02)), ballotMode); err != nil {
		panic(err)
	}
	if err := tree.Add(arbo.BigIntToBytesLE(keyLen, big.NewInt(0x03)), encryptionKey); err != nil {
		panic(err)
	}
	if err := tree.Add(arbo.BigIntToBytesLE(keyLen, big.NewInt(0x04)), resultsAdd.Bytes()); err != nil {
		panic(err)
	}
	if err := tree.Add(arbo.BigIntToBytesLE(keyLen, big.NewInt(0x05)), resultsSub.Bytes()); err != nil {
		panic(err)
	}

	start := 100000
	n := 3000
	v := RandomBytes(keyLen)
	fmt.Printf("value=%x\n", v)
	for i := start; i <= start+n; i++ {
		k := arbo.BigIntToBytesLE(keyLen, big.NewInt(int64(i)))
		if (i-start)%(n/10) == 0 {
			fmt.Printf("adding leaves... i=%d, k=%x, v=%x\n", i, k, v)
		}
		if err := tree.Add(k, v); err != nil {
			panic(err)
		}
	}
	fmt.Println(tree.Root())

	cvp, err := tree.GenerateCircomVerifierProof(arbo.BigIntToBytesLE(keyLen, big.NewInt(int64(start+n))))
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
