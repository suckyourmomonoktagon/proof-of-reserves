package common

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

func TestVerifyAddressRecord_EVM(t *testing.T) {
	err := VerifyAddressRecord(CSVLine{
		DigitalAsset:  "ETH",
		Network:       "ETH",
		Address:       "0x0cdcdb19a857c2ac24818ca4fdfe38cce071483e",
		Message:       "I am an OKX address",
		SignedMessage: "0x07f19879aa28d51c97cddfdfecffe7ed96525545d041aee4f4386b0bf4c1a26924b637fb02ccbb97305c13daa51a0f50b8896fb25ecbaf60020cde920d227a221b",
	})
	if err != nil {
		t.Fatalf("VerifyAddressRecord should verify a standard EVM row: %v", err)
	}
}

func TestVerifyAddressRecord_AptosOwnerMode(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubHex := "0x" + hex.EncodeToString(pub)
	authKey := aptosAuthKey(pub)
	sign := signOKXEd25519(t, priv, aptosOwnerMsg)

	err = VerifyAddressRecord(CSVLine{
		DigitalAsset:  "APTOS",
		Network:       "APTOS",
		Address:       "0x1111",
		Message:       aptosOwnerMsg,
		SignedMessage: sign,
		PublicKey:     pubHex,
		Owner1:        authKey,
	})
	if err != nil {
		t.Fatalf("VerifyAddressRecord should verify an Aptos owner-mode row: %v", err)
	}
}

func TestInitPorCsvDataMapPreservesJSONPublicKeyField(t *testing.T) {
	body := "coin,amount\nEOS,1\n\n" +
		"coin,Type,Network,Snapshot Height,address,amount,message,signature1,signature2,redeem script/ public key,EOA1,EOA2\n" +
		"EOS,Non Staking,EOS,956934,okbwallet1tr,1,I am an OKX address,sig1,sig2,\"{\"\"publicKey1\"\":\"\"pub-1\"\",\"\"publicKey2\"\":\"\"pub-2\"\"}\",,\n"

	m, err := InitPorCsvDataMap(writeTempCSV(t, body))
	if err != nil {
		t.Fatalf("InitPorCsvDataMap failed: %v", err)
	}
	got, ok := m["EOS:okbwallet1tr"]
	if !ok {
		t.Fatalf("expected EOS row to be parsed, got %v", m)
	}
	want := "{\"\"publicKey1\"\":\"\"pub-1\"\",\"\"publicKey2\"\":\"\"pub-2\"\"}"
	if got.Script != want {
		t.Fatalf("Script = %q, want %q", got.Script, want)
	}
}

func TestVerifyAddressRecord_MalformedSignaturesReturnError(t *testing.T) {
	tests := []struct {
		name string
		line CSVLine
	}{
		{
			name: "evm",
			line: CSVLine{
				DigitalAsset:  "ETH",
				Network:       "ETH",
				Address:       "0x0cdcdb19a857c2ac24818ca4fdfe38cce071483e",
				Message:       "I am an OKX address",
				SignedMessage: "0xnothex",
			},
		},
		{
			name: "ecdsa",
			line: CSVLine{
				DigitalAsset:  "FIL",
				Network:       "FIL",
				Address:       "f1testaddress",
				Message:       "I am an OKX address",
				SignedMessage: "0xnothex",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyAddressRecord(tt.line)
			if err == nil {
				t.Fatal("VerifyAddressRecord returned nil error for malformed input")
			}
			if !strings.Contains(err.Error(), "panic") {
				t.Fatalf("VerifyAddressRecord error = %q, want panic-wrapping error", err)
			}
		})
	}
}
