package ethereum

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
	"github.com/umbracle/ethgo/wallet"
	"go.k6.io/k6/js/modules"
)

type Wallet struct{}

type Key struct {
	PrivateKey string
	Address    string
}

func init() {
	wallet := Wallet{}

	modules.Register("k6/x/ethereum/wallet", &wallet)
}

// GenerateKey key creates a random key
func (w *Wallet) GenerateKey() (*Key, error) {
	k, err := wallet.GenerateKey()
	if err != nil {
		return nil, err
	}
	pk, err := k.MarshallPrivateKey()
	if err != nil {
		return nil, err
	}
	pks := hex.EncodeToString(pk)

	return &Key{
		PrivateKey: pks,
		Address:    k.Address().String(),
	}, err
}

func (w *Wallet) DeriveFromMnemonicIndex(mnemonic string, index uint32) (*Key, error) {
	seed := bip39.NewSeed(mnemonic, "")

	return deriveAddress(seed, index)
}

func deriveAddress(seed []byte, index uint32) (*Key, error) {
	// Master key
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, err
	}

	// Derive child key using BIP44 path m/44'/60'/0'/0/index
	purpose, _ := masterKey.NewChildKey(bip32.FirstHardenedChild + 44)
	coinType, _ := purpose.NewChildKey(bip32.FirstHardenedChild + 60)
	account, _ := coinType.NewChildKey(bip32.FirstHardenedChild)
	change, _ := account.NewChildKey(0)
	childKey, _ := change.NewChildKey(index)

	// Generate private key from the derived key
	privateKey, err := crypto.ToECDSA(childKey.Key)
	if err != nil {
		return nil, err
	}

	// Derive the Ethereum address from the private key
	publicKeyECDSA, ok := privateKey.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("error deriving public key")
	}

	return &Key{
		PrivateKey: PrivateKeyToHexString(privateKey),
		Address:    PublicKeyToHexString(publicKeyECDSA),
	}, nil
}

// PrivateKeyToHexString converts a go-ethereum private key to its hexadecimal string representation.
func PrivateKeyToHexString(privateKey *ecdsa.PrivateKey) string {
	// Convert the private key to bytes using go-ethereum's crypto package
	privateKeyBytes := crypto.FromECDSA(privateKey)
	// Encode the bytes to a hexadecimal string
	return hex.EncodeToString(privateKeyBytes)
}

// PublicKeyToHexString converts a go-ethereum public key to its hexadecimal string representation.
func PublicKeyToHexString(publicKey *ecdsa.PublicKey) string {
	// Encode the bytes to a hexadecimal string
	return hex.EncodeToString(crypto.PubkeyToAddress(publicKey))
}
