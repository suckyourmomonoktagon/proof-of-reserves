package common

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func VerifyAddressRecord(line CSVLine) error {
	network := strings.TrimSpace(line.Network)
	addr := strings.TrimSpace(line.Address)
	msg := strings.TrimSpace(line.Message)
	sign1 := strings.TrimSpace(line.SignedMessage)
	sign2 := strings.TrimSpace(line.SignedMessage2)
	publicKey := strings.TrimSpace(line.PublicKey)
	owner1 := strings.TrimSpace(line.Owner1)
	owner2 := strings.TrimSpace(line.Owner2)
	digitalAsset := strings.TrimSpace(line.DigitalAsset)

	if addr == "" || msg == "" || sign1 == "" {
		return fmt.Errorf("missing required parameters (digitalAsset:%s, network:%s, addr:%s)", digitalAsset, network, addr)
	}

	coinType, exists := NetworkType(network)
	if !exists {
		coinType = EcdsaCoinType
	}

	switch coinType {
	case EvmCoinTye:
		if owner1 != "" && owner1 != "null" {
			if err := VerifyEvmCoin(network, owner1, msg, sign1); err != nil {
				if owner2 != "" && owner2 != "null" && sign2 != "" && sign2 != "null" {
					if err2 := VerifyEvmCoin(network, owner2, msg, sign2); err2 != nil {
						return fmt.Errorf("owner1 verification failed: %v, owner2 verification failed: %v", err, err2)
					}
				}
				return fmt.Errorf("owner1 verification failed: %v", err)
			}
			if owner2 != "" && owner2 != "null" && sign2 != "" && sign2 != "null" {
				if err := VerifyEvmCoin(network, owner2, msg, sign2); err != nil {
					return fmt.Errorf("owner2 verification failed: %v", err)
				}
			}
			return nil
		}
		return VerifyEvmCoin(network, addr, msg, sign1)
	case EcdsaCoinType:
		if owner1 != "" && owner1 != "null" {
			if err := VerifyEcdsaCoin(network, owner1, msg, sign1); err != nil {
				if owner2 != "" && owner2 != "null" && sign2 != "" && sign2 != "null" {
					if err2 := VerifyEcdsaCoin(network, owner2, msg, sign2); err2 != nil {
						return fmt.Errorf("owner1 verification failed: %v, owner2 verification failed: %v", err, err2)
					}
				}
				return fmt.Errorf("owner1 verification failed: %v", err)
			}
			if owner2 != "" && owner2 != "null" && sign2 != "" && sign2 != "null" {
				if err := VerifyEcdsaCoin(network, owner2, msg, sign2); err != nil {
					return fmt.Errorf("owner2 verification failed: %v", err)
				}
			}
			return nil
		}
		if publicKey != "" && publicKey != "null" && publicKey != "\\N" {
			return VerifyEcdsaCoinWithPub(msg, sign1, publicKey)
		}
		return VerifyEcdsaCoin(network, addr, msg, sign1)
	case Ed25519CoinType:
		if publicKey == "" || publicKey == "null" {
			return fmt.Errorf("ED25519 coin %s missing public key (digitalAsset:%s)", network, digitalAsset)
		}
		if owner1 != "" && owner1 != "null" {
			return VerifyEd25519Coin(network, owner1, msg, sign1, publicKey)
		}
		return VerifyEd25519Coin(network, addr, msg, sign1, publicKey)
	case TrxCoinType:
		return VerifyTRX(addr, msg, sign1)
	case BethCoinType:
		return VerifyBETH(addr, msg, sign1)
	case UTXOCoinType:
		return VerifyUtxoCoin(network, addr, msg, sign1, sign2, publicKey)
	case StarkCoinType:
		if publicKey == "" || publicKey == "null" {
			return fmt.Errorf("STARK coin %s missing public key (digitalAsset:%s)", network, digitalAsset)
		}
		return VerifyStarkCoin(network, addr, msg, sign1, publicKey)
	case EOSCoinType:
		if publicKey == "" || publicKey == "null" {
			return fmt.Errorf("EOS coin %s missing public key (digitalAsset:%s)", network, digitalAsset)
		}

		cleanKey := strings.TrimSpace(publicKey)
		if strings.HasPrefix(cleanKey, "\"") && strings.HasSuffix(cleanKey, "\"") {
			cleanKey = cleanKey[1 : len(cleanKey)-1]
			cleanKey = strings.ReplaceAll(cleanKey, "\"\"", "\"")
		}

		if strings.HasPrefix(cleanKey, "{") {
			var pubKeys map[string]string
			if json.Unmarshal([]byte(cleanKey), &pubKeys) != nil {
				return fmt.Errorf("invalid JSON public key format")
			}
			err1 := VerifyEOSCoin(network, addr, msg, sign1, pubKeys["publicKey1"])
			err2 := VerifyEOSCoin(network, addr, msg, sign2, pubKeys["publicKey2"])
			if err1 != nil || err2 != nil {
				return fmt.Errorf("EOS dual signature failed: sig1=%v, sig2=%v", err1, err2)
			}
			return nil
		}
		return VerifyEOSCoin(network, addr, msg, sign1, publicKey)
	default:
		return fmt.Errorf("unsupported coin type %s (digitalAsset:%s, network:%s)", coinType, digitalAsset, network)
	}
}

// Verify single line data (single-threaded version, only handle StarkNet)
func verifyCSVLineStarknetOnly(coin, addr, msg, sign1, sign2, publicKey, digitalAsset string, lineNumber int, t *testing.T) (bool, string, string) {
	// Check if it's StarkNet coin, skip if not
	coinType, exists := NetworkType(coin)
	if !exists || coinType != StarkCoinType {
		return true, coin, ""
	}

	return verifyCSVLineInternal(coin, addr, msg, sign1, sign2, publicKey, "", "", digitalAsset, lineNumber, t)
}

// Verify single line data (multithreaded version, skip StarkNet)
func verifyCSVLineMultithread(coin, addr, msg, sign1, sign2, publicKey, owner1, owner2, digitalAsset string, lineNumber int, t *testing.T) (bool, string, string) {
	// Check if it's StarkNet coin, skip multithreaded verification if yes
	coinType, exists := NetworkType(coin)
	if exists && coinType == StarkCoinType {
		return true, coin, ""
	}

	return verifyCSVLineInternal(coin, addr, msg, sign1, sign2, publicKey, owner1, owner2, digitalAsset, lineNumber, t)
}

// Internal verification logic (shared)
func verifyCSVLineInternal(coin, addr, msg, sign1, sign2, publicKey, owner1, owner2, digitalAsset string, lineNumber int, t *testing.T) (bool, string, string) {
	err := VerifyAddressRecord(CSVLine{
		LineNumber:     lineNumber,
		DigitalAsset:   digitalAsset,
		Network:        coin,
		Address:        addr,
		SignedMessage:  sign1,
		SignedMessage2: sign2,
		Message:        msg,
		PublicKey:      publicKey,
		Owner1:         owner1,
		Owner2:         owner2,
	})
	if err != nil {
		errorMsg := fmt.Sprintf("Verification failed: %v", err)
		t.Logf("Line %d verification failed: %s (digitalAsset:%s, network:%s, addr:%s, error:%v)", lineNumber, coin, digitalAsset, coin, addr, err)
		return false, coin, errorMsg
	}

	return true, coin, ""
}
