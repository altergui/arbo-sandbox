package main

import (
	"bytes"
	"crypto/rand"
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

	keyLen := 1
	maxLevels := keyLen * 8
	tree, err := arbo.NewTree(arbo.Config{
		Database: database, MaxLevels: maxLevels,
		HashFunction: arbo.HashFunctionBlake3,
	})
	if err != nil {
		panic(err)
	}

	processID := []byte("01234567890123456789012345678900")
	censusRoot := []byte("01234567890123456789012345678901")
	ballotMode := []byte("1234")
	encryptionKey := []byte("01234567890123456789012345678902")
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

	root, _ := tree.Root()
	fmt.Printf("%x\n", root)

	cvp1 := make(map[int64]*arbo.CircomVerifierProof)

	stateVersion := 1
	for i := int64(0x00); i <= int64(0x05); i++ {
		cvp1[i], err = tree.GenerateCircomVerifierProof(arbo.BigIntToBytesLE(keyLen, big.NewInt(i)))
		if err != nil {
			panic(err)
		}

		jCvp, err := json.Marshal(cvp1[i])
		if err != nil {
			panic(err)
		}
		file := fmt.Sprintf("state%dmerkleproof%d.json", stateVersion, i)
		if err := os.WriteFile(file, jCvp, os.ModePerm); err != nil {
			panic(err)
		}
	}

	cvp2 := make(map[int64]*arbo.CircomVerifierProof)

	stateVersion = 2

	censusRoot[0] = byte(0x02)
	encryptionKey[0] = byte(0x02)

	if err := tree.Update(arbo.BigIntToBytesLE(keyLen, big.NewInt(0x01)), censusRoot); err != nil {
		panic(err)
	}
	if err := tree.Update(arbo.BigIntToBytesLE(keyLen, big.NewInt(0x03)), encryptionKey); err != nil {
		panic(err)
	}

	for i := int64(0x00); i <= int64(0x05); i++ {
		cvp2[i], err = tree.GenerateCircomVerifierProof(arbo.BigIntToBytesLE(keyLen, big.NewInt(i)))
		if err != nil {
			panic(err)
		}

		jCvp, err := json.Marshal(cvp2[i])
		if err != nil {
			panic(err)
		}
		file := fmt.Sprintf("state%dmerkleproof%d.json", stateVersion, i)
		if err := os.WriteFile(file, jCvp, os.ModePerm); err != nil {
			panic(err)
		}
	}

	fmt.Printf("root: %x =? %x\n", cvp1[0].Root, cvp2[0].Root)

	rootMap := make(map[string]int)
	newSiblings := make(map[string]int)
	for i := int64(0x00); i <= int64(0x05); i++ {
		fmt.Printf("\n")
		for k, s := range cvp1[i].Siblings {
			fmt.Printf("siblings %d/%d: %x =? %x", i, k, s, cvp2[i].Siblings[int64(k)])
			if !slices.Equal(s, cvp2[i].Siblings[int64(k)]) {
				fmt.Printf(" <<< diff")
			}
			fmt.Printf("\n")
		}
		if !slices.Equal(cvp1[i].Value, cvp2[i].Value) {
			fmt.Printf("value %d: %x != %x <<<<<< diff\n", i, cvp1[i].Value, cvp2[i].Value)
			hash, err := tree.HashFunction().Hash(cvp2[i].Key, cvp2[i].Value, []byte{1})
			if err != nil {
				panic(err)
			}
			fmt.Printf("hash %x\n", hash)

			fmt.Printf("\n\nwill CollectProofHashes to go from k(%x)=v(%x) to root(%x)\n",
				cvp2[i].Key,
				cvp2[i].Value,
				cvp2[i].Root,
			)

			roots, err := cvp2[i].CalculateProofNodes(tree.HashFunction())
			if err != nil {
				panic(err)
			}
			if !bytes.Equal(cvp2[i].Root, roots[0]) {
				panic("root doesn't match")
			}

			for i, r := range roots {
				rootMap[hex.EncodeToString(r)] = i
				fmt.Printf("root(%d): %x\n", i, r)
			}

			for si, s := range cvp2[i].Siblings {
				if !slices.Equal(cvp1[i].Siblings[si], cvp2[i].Siblings[si]) {
					newSiblings[hex.EncodeToString(s)] = si + 1
				}
			}
		}
	}

	fmt.Println("\n\ni derived all these hashes from the proofs\n", rootMap)
	fmt.Println("the proofs had these new siblings\n", newSiblings)

	for k, v := range newSiblings {
		if rootMap[k] != v {
			fmt.Printf("given this set of proofs, i can't explain why sibling %s (at level %d) changed\n", k, v)
			return
		}
	}
	fmt.Println("set of proofs verified, there were no other changes to the tree")
}

func TestProofWith256Levels() {
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
