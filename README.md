# wallet-tool
Example app to control the wallet. Supported commands include listing slots,
resetting the token, generating and deleting key pairs via PKCS#11.

```
python main.py --generate-key ed25519 --pin 0000
python main.py --delete-key 1 --pin 0000
```
