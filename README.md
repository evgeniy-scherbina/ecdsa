# ecdsa

### Install
```
git clone https://github.com/evgeniy-scherbina/ecdsa
cd $GOPATH/src/github.com/evgeniy-scherbina/ecdsa
dep ensure
go build
```

### Usage

```
./ecdsa gen_keys
PrivateKey: 6f42acf96911b35030b6bbb694bc3c3a1fc48ce339c3ddbb16bb7d2915372541
PublicKey:  0332e47122028b9d880d1e9f6feb6b066f0413c26098bc356d3dc427815492b9e7
```

```
./ecdsa sign --message=some_message
PrivateKey: 6f42acf96911b35030b6bbb694bc3c3a1fc48ce339c3ddbb16bb7d2915372541
PublicKey:  0332e47122028b9d880d1e9f6feb6b066f0413c26098bc356d3dc427815492b9e7
signatureHex: 304402205910dde4e5bf8638790b09a66a29082b969bb15877bc58947ab36f076c92dbe8022048504bfeb5de21ef5d5eb443a45cf3dc19c1ef73adfa00bf1c3fec061293e5cc
```

### Message Format
`BitcoinAddress + MerchantId + NtfnUrl + NtfnUrlForForwardPayment + NtfnUrlForOnChainPayment` without any separators
