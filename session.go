package walletcore

import (
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/accounts/keystore"
)

type sessionState struct {
	unlockedKeys map[string]*keystore.Key
	expiresAt    time.Time
}

const sessionTTL = 30 * time.Minute

func (m *manager) UnlockWallets(password string) error {
	if len(m.wallets) == 0 {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	unlocked := make(map[string]*keystore.Key)
	for _, w := range m.wallets {
		key, err := keystore.DecryptKey(w.KeyJSON, password)
		if err != nil {
			// zero any partially decrypted keys
			return fmt.Errorf("invalid password: %w", err)
		}

		unlocked[w.ID] = key
	}

	m.session = &sessionState{
		unlockedKeys: unlocked,
		expiresAt:    time.Now().Add(sessionTTL),
	}

	// start session janitor
	go m.startSessionJanitor()

	return nil
}

func (m *manager) lockWallets() {
	m.mu.Lock()
	if m.session != nil {
		for _, key := range m.session.unlockedKeys {
			zeroECDSAKey(key.PrivateKey)
		}
		m.session = nil
	}
	m.mu.Unlock()
}

func (m *manager) isSessionExpired() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.session == nil {
		return true
	}

	return time.Now().After(m.session.expiresAt)
}

func (m *manager) startSessionJanitor() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		if m.isSessionExpired() {
			m.lockWallets()
			break
		}
	}
}

func (m *manager) IsUnlocked() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.session != nil && time.Now().Before(m.session.expiresAt)
}
