# wallet-tool
Example app to control the wallet. Supported commands include listing slots,
resetting the token, generating and deleting key pairs, as well as changing the
user PIN via PKCS#11.
When generating a key pair both ``--key-id`` and ``--key-label`` must be
specified.

```
python main.py --generate-key ed25519 --pin 0000 --key-id myid --key-label mylabel
python main.py --generate-key gost --pin 0000 --key-id myid --key-label mylabel
python main.py --delete-key 1 --pin 0000
python main.py --change-pin --pin 0000 --new-pin 1234
```
GOST key generation also requires ``--key-id`` and ``--key-label``.
