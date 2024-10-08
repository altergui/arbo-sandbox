package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/db/metadb"
	"go.vocdoni.io/dvote/tree/arbo"
)

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
		Database: database, MaxLevels: 4,
		HashFunction: arbo.HashFunctionPoseidon,
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
		k := arbo.BigIntToBytes(bLen, big.NewInt(testVector[i][0]))
		v := arbo.BigIntToBytes(bLen, big.NewInt(testVector[i][1]))
		if err := tree.Add(k, v); err != nil {
			panic(err)
		}
	}

	// proof of existence (fnc = 0: inclusion, 1: non inclusion)
	k := arbo.BigIntToBytes(bLen, big.NewInt(int64(2)))
	cvp, err := tree.GenerateCircomVerifierProof(k)
	if err != nil {
		panic(err)
	}

	jCvp, err := json.Marshal(cvp)
	if err != nil {
		panic(err)
	}

	// test vector checked with a circom circuit (arbo/testvectors/circom)
	if string(jCvp) != `{"fnc":0,"isOld0":"0","key":"2","oldK`+
		`ey":"0","oldValue":"0","root":"1355816845522055904274785395894906304622`+
		`6645447188878859760119761585093422436","siblings":["1162013050763544193`+
		`2056895853942898236773847390796721536119314875877874016518","5158240518`+
		`874928563648144881543092238925265313977134167935552944620041388700","0"`+
		`,"0"],"value":"22"}` {
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
	k = arbo.BigIntToBytes(bLen, big.NewInt(int64(5)))
	cvp, err = tree.GenerateCircomVerifierProof(k)
	if err != nil {
		panic(err)
	}
	jCvp, err = json.Marshal(cvp)
	if err != nil {
		panic(err)
	}
	// test vector checked with a circom circuit (arbo/testvectors/circom)
	if string(jCvp) != `{"fnc":1,"isOld0":"0","key":"5","oldK`+
		`ey":"1","oldValue":"11","root":"135581684552205590427478539589490630462`+
		`26645447188878859760119761585093422436","siblings":["756056982086999933`+
		`1905412009838015295115276841209205575174464206730109811365","1276103081`+
		`3800436751877086580591648324911598798716611088294049841213649313596","0`+
		`","0"],"value":"11"}` {
		panic("")
	}

	fmt.Println(hex.EncodeToString(jCvp))
}
