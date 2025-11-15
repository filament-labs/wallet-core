package walletcore

import (
	"errors"
	"time"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/filecoin-project/go-address"
)

var (
	ErrWalletNotFound      = errors.New("wallet not found")
	ErrInvalidMnemonic     = errors.New("invalid mnemonic phrase")
	ErrInvalidPassphrase   = errors.New("invalid passphrase")
	ErrInvalidWalletName   = errors.New("invalid wallet name")
	ErrDuplicateWalletName = errors.New("duplicate wallet name")
	ErrWalletLocked        = errors.New("wallet is locked")
	ErrInsufficientBalance = errors.New("insufficient balance")
	ErrInvalidAddress      = errors.New("invalid address")
	ErrTransactionFailed   = errors.New("transaction failed")
)

// Wallet represents a Filecoin wallet with encrypted storage
type Wallet struct {
	ID        string            `json:"id"`
	IsDefault bool              `json:"is_default"`
	Name      string            `json:"name"`
	Mnemonic  string            `json:"-"`
	KeyJSON   []byte            `json:"key_json"`
	Addrs     map[string]string `json:"addresses"`
	Meta      map[string]string `json:"metadata"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`

	key *keystore.Key
}

// Transaction represents a Filecoin transaction
type Transaction struct {
	Cid        string    `json:"cid"`
	From       string    `json:"from"`
	To         string    `json:"to"`
	Value      string    `json:"value"`
	GasFeeCap  string    `json:"gas_fee_cap"`
	GasPremium string    `json:"gas_premium"`
	GasLimit   int64     `json:"gas_limit"`
	Nonce      uint64    `json:"nonce"`
	Method     uint64    `json:"method"`
	Params     []byte    `json:"params,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
	Height     int64     `json:"height"`
	Status     string    `json:"status"` // "pending", "confirmed", "failed"
}

// Balance represents wallet balance information
type Balance struct {
	Address   string    `json:"address"`
	Balance   string    `json:"balance"` // in attoFIL
	Nonce     uint64    `json:"nonce"`
	Timestamp time.Time `json:"timestamp"`
}

// WalletStore defines the interface for wallet persistence
type WalletStore interface {
	// Save stores a wallet securely
	Save(wallet *Wallet) error

	// Get retrieves a wallet by ID
	Get(id string) (*Wallet, error)

	// List returns all wallets
	List() ([]*Wallet, error)

	// Delete removes a wallet
	Delete(id string) error

	// Update modifies an existing wallet
	Update(wallet *Wallet) error
}

// RPCConfig contains RPC endpoint configuration
type RPCConfig struct {
	Endpoint string
	Token    string
	Timeout  time.Duration
}

// GasEstimate represents gas estimation for a transaction
type GasEstimate struct {
	GasLimit   int64
	GasFeeCap  string
	GasPremium string
}

// SendOptions contains options for sending transactions
type SendOptions struct {
	From       address.Address
	To         address.Address
	Value      string // in attoFIL
	GasLimit   *int64
	GasFeeCap  *string
	GasPremium *string
	Method     uint64
	Params     []byte
}

type AddressType string

const (
	AddressTypeF1  AddressType = "f1"
	AddressTypeF4  AddressType = "f4"
	AddressTypeEth AddressType = "0x"
)

func (t AddressType) Valid() bool {
	switch t {
	case AddressTypeF1, AddressTypeF4, AddressTypeEth:
		return true
	}
	return false
}
