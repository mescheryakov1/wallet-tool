# wallet-tool
Example app to control the wallet. Supported commands include listing slots,
resetting the token, generating and deleting key pairs, as well as changing the
user PIN via PKCS#11. Commands that operate on a specific wallet accept the
``--wallet-id`` option; when omitted, wallet identifier ``0`` is used. Unless
stated otherwise, examples use the factory user PIN ``12345678`` passed via the
``--pin`` option when a command requires authentication.
When generating a key pair both ``--key-id`` and ``--key-label`` must be
specified.

```
python main.py --generate-key ed25519 --wallet-id 0 --pin 12345678 --key-id myid --key-label mylabel
python main.py --generate-key gost --wallet-id 0 --pin 12345678 --key-id myid --key-label mylabel
python main.py --delete-key 1 --wallet-id 0 --pin 12345678
python main.py --change-pin --wallet-id 0 --pin 12345678 --new-pin 1234
```
GOST key generation also requires ``--key-id`` and ``--key-label``.
