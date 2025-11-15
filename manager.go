package walletcore

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/google/uuid"
)

type Manager interface {
	LoadWallets(ctx context.Context) ([]Wallet, error)
	CreateWallet(ctx context.Context, walletName, keystorePassphrase string) (*Wallet, error)
	RecoverWallet(ctx context.Context, seedPhrase, walletName, password string) (*Wallet, error)
	DeleteWallet(walletID string) error
}

type manager struct {
	rpcClient *RPCClient
	db        *db
	dataDir   string
	wallets   map[string]Wallet
	session   *sessionState
	mu        sync.RWMutex
}
type ManagerOption func(*manager) error

// WithRPC allows setting a custom RPC endpoint and optional token
func WithOptions(url, token string) ManagerOption {
	return func(m *manager) error {
		if url == "" {
			url = "https://filfox.info/rpc/v1"
		}
		rpcClient, err := NewRPCClient(RPCConfig{
			Endpoint: url,
			Token:    token,
		})
		if err != nil {
			return fmt.Errorf("failed to initialize RPC client: %w", err)
		}
		m.rpcClient = rpcClient
		return nil
	}
}

// NewManager initializes a Manager with Badger DB and optional configurations
func NewManager(dataDir string, opts ...ManagerOption) (Manager, error) {
	db, err := newDB(filepath.Join(dataDir, "db"))
	if err != nil {
		return nil, err
	}

	m := &manager{
		db:      db,
		dataDir: dataDir,
		wallets: make(map[string]Wallet),
	}

	// Apply options
	for _, opt := range opts {
		if err := opt(m); err != nil {
			return nil, err
		}
	}

	// If no RPC option was applied, initialize with default
	if m.rpcClient == nil {
		rpcClient, err := NewRPCClient(RPCConfig{
			Endpoint: "https://filfox.info/rpc/v1",
		})
		if err != nil {
			return nil, fmt.Errorf("failed to initialize default RPC client: %w", err)
		}
		m.rpcClient = rpcClient
	}

	return m, nil
}

func (m *manager) LoadWallets(ctx context.Context) ([]Wallet, error) {
	wallets, err := m.db.GetWallets()
	if err != nil {
		return nil, fmt.Errorf("error loading wallets: %w", err)
	}

	m.wallets = map[string]Wallet{}

	for _, wal := range wallets {
		m.wallets[wal.ID] = wal
	}

	return nil, nil
}

// CreateWallet generates a brand-new wallet, persists it, and returns the in-memory instance (locked).
func (m *manager) CreateWallet(ctx context.Context, walletName, keystorePassphrase string) (*Wallet, error) {
	if keystorePassphrase == "" {
		return nil, ErrInvalidPassphrase
	}

	if walletName == "" {
		return nil, ErrInvalidWalletName
	}

	// Generate new mnemonic (12 words)
	mnemonic, err := GenerateMnemonic(128)
	if err != nil {
		return nil, fmt.Errorf("error generating mnemonic: %w", err)
	}

	return m.createWalletFromMnemonic(mnemonic, walletName, keystorePassphrase, false)
}

// RecoverWallet recovers a wallet from a mnemonic phrase
func (m *manager) RecoverWallet(ctx context.Context, mnemonic, name, keystorePassphrase string) (*Wallet, error) {
	if !ValidateMnemonic(mnemonic) {
		return nil, ErrInvalidMnemonic
	}

	if keystorePassphrase == "" {
		return nil, ErrInvalidPassphrase
	}

	return m.createWalletFromMnemonic(mnemonic, name, keystorePassphrase, true)
}

// createWalletFromMnemonic creates a wallet from a mnemonic phrase
func (m *manager) createWalletFromMnemonic(mnemonic, name, keystorePassphrase string, recovered bool) (*Wallet, error) {
	// Generate seed from mnemonic
	seed := MnemonicToSeed(mnemonic, "")

	// Derive private key
	privKey, err := derivePrivateKeyFromSeed(seed)
	if err != nil {
		return nil, fmt.Errorf("derive private key: %w", err)
	}

	// Create keystore encryption
	ks := keystore.NewKeyStore(getKeyStoreDir(m.dataDir), keystore.StandardScryptN, keystore.StandardScryptP)
	account, err := ks.ImportECDSA(privKey, keystorePassphrase)
	if err != nil {
		return nil, fmt.Errorf("import ecdsa: %w", err)
	}

	keyJSON, err := ks.Export(account, keystorePassphrase, keystorePassphrase)
	if err != nil {
		return nil, fmt.Errorf("export keystore: %w", err)
	}

	// Derive addresses
	addrs, err := DeriveAddressFromPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("derive addresses: %w", err)
	}

	now := time.Now()
	wallet := &Wallet{
		ID:        uuid.NewString(),
		Name:      name,
		Mnemonic:  mnemonic,
		KeyJSON:   keyJSON,
		Addrs:     addrs,
		Meta:      make(map[string]string),
		CreatedAt: now,
		UpdatedAt: now,
	}

	if recovered {
		wallet.Meta["recovered"] = "true"
	}

	err = m.db.SaveWallet(wallet)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.wallets[wallet.ID] = *wallet

	key, err := m.UnlockWallet(*wallet, keystorePassphrase)
	if err != nil {
		return nil, err
	}

	unlockedWallets := m.session.unlockedKeys
	unlockedWallets[wallet.ID] = key
	m.session.unlockedKeys = unlockedWallets

	return wallet, nil
}

func (m *manager) DeleteWallet(walletID string) error {

	m.mu.Lock()
	defer m.mu.Unlock()

	// TODO

	return nil
}
