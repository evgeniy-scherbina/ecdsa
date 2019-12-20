package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
			cli.BoolFlag{
				Name:  "sha256",
				Usage: "use sha256 as hash function (default is ripemd160(sha256(b)))",
			},
		},
		Action: sign,
	}
	verifyCmd = cli.Command{
		Name:  "verify",
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "public_key",
			},
			cli.StringFlag{
				Name: "message",
			},
			cli.StringFlag{
				Name: "signature",
			},
			cli.BoolFlag{
				Name:  "sha256",
				Usage: "use sha256 as hash function (default is ripemd160(sha256(b)))",
			},
		},
		Action: verify,
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
	var messageHash []byte
	if ctx.Bool("sha256") {
		rez := sha256.Sum256(message)
		messageHash = rez[:]
	} else {
		messageHash = btcutil.Hash160(message)
	}

	signature, err := privKey.Sign(messageHash)
	if err != nil {
		return err
	}

	signatureHex := hex.EncodeToString(signature.Serialize())
	fmt.Printf("signatureHex: %v\n", signatureHex)

	return nil
}

func verify(ctx *cli.Context) error {
	publicKeyHex := ctx.String("public_key")
	publicKeyRaw, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return err
	}
	publicKey, err := btcec.ParsePubKey(publicKeyRaw, btcec.S256())
	if err != nil {
		return err
	}

	message := []byte(ctx.String("message"))
	var messageHash []byte
	if ctx.Bool("sha256") {
		rez := sha256.Sum256(message)
		messageHash = rez[:]
	} else {
		messageHash = btcutil.Hash160(message)
	}

	signatureHex := ctx.String("signature")
	signatureRaw, err := hex.DecodeString(signatureHex)
	if err != nil {
		return err
	}
	signature , err := btcec.ParseDERSignature(signatureRaw, btcec.S256())
	if err != nil {
		return err
	}

	if !signature.Verify(messageHash, publicKey) {
		return errors.New("invalid signature")
	}
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
		verifyCmd,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal("cannot run app:", err)
		return
	}
}
