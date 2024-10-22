package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"slices"
	"testing"

	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/db/metadb"
	"go.vocdoni.io/dvote/tree/arbo"
)

func TestMockProof(t *testing.T) {
	dir, err := os.MkdirTemp("", "arbosandbox")
	if err != nil {
		panic(err)
	}

	database, err := metadb.New(db.TypePebble, dir)
	if err != nil {
		panic(err)
	}

	tree, err := arbo.NewTree(arbo.Config{
		Database: database, MaxLevels: 4,
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
		`"0","root":"21347616572972183420218629198567600327562992672406197041775040089740136115868",`+
		`"siblings":["89414254218799143202750356849973752051553644818384431923446349453527984244840",`+
		`"100272205498883598074187859649410185367157757359872275599596420039979979515420","0","0"],`+
		`"value":"22"}` {
		panic("")
	}
	fmt.Println("root", arbo.BytesLEToBigInt(cvp.Root))
	fmt.Println("key", arbo.BytesLEToBigInt(cvp.Key))
	fmt.Println("value", arbo.BytesLEToBigInt(cvp.Value))
	for _, s := range cvp.Siblings {
		fmt.Println("siblings", arbo.BytesLEToBigInt(s))
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
		`"oldValue":"11","root":"21347616572972183420218629198567600327562992672406197041775040089740136115868",`+
		`"siblings":["2366253119233799318008910714979258399506332162845231905696183084132066720517",`+
		`"61093584903451702856702332824323051875980263396096817106018703936895272494632","0","0"],`+
		`"value":"11"}` {
		panic("")
	}
}
