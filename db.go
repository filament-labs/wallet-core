package walletcore

import (
	"fmt"

	"github.com/nutsdb/nutsdb"
)

type db struct {
	*nutsdb.DB
}

const (
	walletsBucket = "wallets"
)

func getTransactionBucket(walletID string) string {
	return "wallet:" + walletID + ":txs"
}

func newDB(dbPath string) (*db, error) {
	dbConn, err := nutsdb.Open(
		nutsdb.DefaultOptions,
		nutsdb.WithDir(dbPath),
	)

	if err != nil {
		return nil, fmt.Errorf("error opening database: %w", err)
	}

	return &db{
		dbConn,
	}, nil
}

func (d *db) close() error {
	if d.DB != nil {
		return d.DB.Close()
	}

	return nil
}

func (db *db) CreateBucket(bucket string) error {
	return db.Update(func(tx *nutsdb.Tx) error {
		return tx.NewBucket(nutsdb.DataStructureBTree, bucket)
	})
}

func (db *db) GetWallets() ([]Wallet, error) {
	var wallets []Wallet

	err := db.View(func(tx *nutsdb.Tx) error {
		_, values, err := tx.GetAll(walletsBucket)
		if err != nil {
			if err == nutsdb.ErrBucketNotExist {
				return nil
			}

			return err
		}

		for _, val := range values {
			var w Wallet
			if err := Decode(val, &w); err != nil {
				return err
			}
			wallets = append(wallets, w)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return wallets, nil
}

func (db *db) GetWalletTransactions(walletID string, offset, num int) ([]Transaction, error) {

	return nil, nil
}

func (db *db) SaveWallet(wallet *Wallet) error {
	walletBytes, err := Encode(wallet)
	if err != nil {
		return fmt.Errorf("error encoding wallet data: %w", err)
	}

	err = db.Update(func(txn *nutsdb.Tx) error {
		return txn.Put(walletsBucket, []byte(wallet.ID), walletBytes, 0)
	})

	return err
}
