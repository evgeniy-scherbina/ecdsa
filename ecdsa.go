package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil"
	"github.com/urfave/cli"
)

const (
	defaultKeysPath = "/tmp/keys.json"

	tmpl = `
PrivateKey: %v
PublicKey:  %v
`
)

var (
	genKeysCmd = cli.Command{
		Name:  "gen_keys",
		Usage: "Generation private and public key",
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "path",
				Value: defaultKeysPath,
			},
		},
		Action: genKeys,
	}
	signCmd = cli.Command{
		Name:  "sign",
		Usage: "Sign given message with previously generated private key",
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "path",
				Value: defaultKeysPath,
			},
			cli.StringFlag{
				Name: "message",
			},
		},
		Action: sign,
	}
)

func genKeys(ctx *cli.Context) error {
	privKey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		return err
	}
	privKeyHex := hex.EncodeToString(privKey.Serialize())

	pubKeyRaw := privKey.PubKey().SerializeCompressed()
	pubKeyHex := hex.EncodeToString(pubKeyRaw)

	fmt.Printf(tmpl, privKeyHex, pubKeyHex)

	return ioutil.WriteFile(ctx.String("path"), []byte(privKeyHex), 0666)
}

func sign(ctx *cli.Context) error {
	privKeyHex, err := ioutil.ReadFile(ctx.String("path"))
	if err != nil {
		return err
	}
	privKeyRaw, err := hex.DecodeString(string(privKeyHex))
	if err != nil {
		return err
	}
	privKey, pubKey := btcec.PrivKeyFromBytes(btcec.S256(), privKeyRaw)

	pubKeyRaw := pubKey.SerializeCompressed()
	pubKeyHex := hex.EncodeToString(pubKeyRaw)

	fmt.Printf(tmpl, string(privKeyHex), pubKeyHex)

	message := []byte(ctx.String("message"))
	messageHash := btcutil.Hash160(message)

	signature, err := privKey.Sign(messageHash)
	if err != nil {
		return err
	}

	signatureHex := hex.EncodeToString(signature.Serialize())
	fmt.Printf("signatureHex: %v\n", signatureHex)

	return nil
}

func main() {
	app := cli.NewApp()

	app.Name = "ecdsa"
	app.Usage = "Command line interface for btcec library"
	app.Version = "1.0.0"
	app.Compiled = time.Now()
	app.Commands = []cli.Command{
		genKeysCmd,
		signCmd,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal("cannot run app:", err)
		return
	}
}
