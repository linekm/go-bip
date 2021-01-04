package bip44

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/linekm/go-bip/go-bip32"
	"github.com/linekm/go-bip/go-bip39"
)

func TestFunctions(t *testing.T) {
	str := "0xabcd"
	src := strings.Split(str, "0x")
	var dst []byte = make([]byte, len(src[1])/2)
	hex.Decode(dst, []byte(str))
	fmt.Println(dst)
}

func TestNewKeyFromMnemonic(t *testing.T) {
	mnemonic := "hold scale hybrid tank dilemma bullet ship language attitude rug tennis host"
	fKey, _ := NewKeyFromMnemonic(mnemonic, TypeEther, bip32.FirstHardenedChild, 0, 0)
	t.Log(fKey.Key)
	t.Logf("%x", fKey.Key)
	pubKey := fKey.PublicKey().Key
	t.Log(len(pubKey))
	t.Logf("%x", pubKey)
	addr := fKey.PublicKey().Address()
	t.Logf("%x", addr.Bytes())
}

func TestNewKeyFromMasterKey(t *testing.T) {
	mnemonic := "hold scale hybrid tank dilemma bullet ship language attitude rug tennis host"

	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, "")
	if err != nil {
		panic(err)
	}

	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		panic(err)
	}

	fKey, err := NewKeyFromMasterKey(masterKey, TypeFactomFactoids, bip32.FirstHardenedChild, 0, 0)
	if err != nil {
		panic(err)
	}
	if fKey.String() != "xprvA2vH8KdcBBKhMxhENJpJdbwiU5cUXSkaHR7QVTpBmusgYMR8NsZ4BFTNyRLUiaPHg7UYP8u92FJkSEAmmgu3PDQCoY7gBsdvpB7msWGCpXG" {
		t.Errorf("Invalid Factoid key - %v", fKey.String())
	}

	ecKey, err := NewKeyFromMasterKey(masterKey, TypeFactomEntryCredits, bip32.FirstHardenedChild, 0, 0)
	if err != nil {
		panic(err)
	}
	if ecKey.String() != "xprvA2ziNegvZRfAAUtDsjeS9LvCP1TFXfR3hUzMcJw7oYAhdPqZyiJTMf1ByyLRxvQmGvgbPcG6Q569m26ixWsmgTR3d3PwicrG7hGD7C7seJA" {
		t.Errorf("Invalid EC key - %v", ecKey.String())
	}
}

/*
func TestTest(t *testing.T) {
	//var factoidHex uint32 = 0x80000083
	//var ecHex uint32 = 0x80000084

	mnemonic := "yellow yellow yellow yellow yellow yellow yellow yellow yellow yellow yellow yellow"

	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, "")
	if err != nil {
		panic(err)
	}

	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		panic(err)
	}

	child, err := masterKey.NewChildKey(bip32.FirstHardenedChild + 44)
	if err != nil {
		panic(err)
	}
	t.Logf("%v", child.String())

	child, err = child.NewChildKey(bip32.FirstHardenedChild + 132)
	if err != nil {
		panic(err)
	}
	t.Logf("%v", child.String())

	child, err = child.NewChildKey(bip32.FirstHardenedChild)
	if err != nil {
		panic(err)
	}
	t.Logf("%v", child.String())

	child, err = child.NewChildKey(0)
	if err != nil {
		panic(err)
	}
	t.Logf("%v", child.String())

	child, err = child.NewChildKey(0)
	if err != nil {
		panic(err)
	}
	t.Logf("%v", child.String())

	/*
		if child.String()!="xprvA22bpQKA9av7gEKdskwxbBNaMso6XpmW7sXi5LGgKnGCMe82BYW68tcNXtn4ZiLHDYJ2HpRvknV7zdDSgBXtPo4dRwG8XCcU55akAcarx3G" {

		}
*/ /*

	key, err := NewKeyFromMnemonic(mnemonic, bip32.FirstHardenedChild, 0, 0, 0)
	if err != nil {
		panic(err)
	}
	t.Logf("%v", key.String())

	add, err := factom.MakeFactoidAddress(key.Key)
	if err != nil {
		panic(err)
	}
	t.Logf("%v", add.String())

	t.FailNow()
}
*/
