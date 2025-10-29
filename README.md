# wallet-tool
Example app to control the wallet. Supported commands include listing slots,
resetting the token (deleting all objects), generating, importing and deleting 
key pairs, as well as changing the user PIN-code. Commands that operate on a 
specific wallet accept the``--wallet-id`` option; when omitted, wallet 
identifier ``0`` is used. PIN-code passed via the``--pin`` option when a command 
requires authentication. When generating a key pair both ``--key-id`` and 
``--key-label`` must be specified. Use ``--get-mnemonic`` to get mnemonic phrase 
during key pair generation. ``--force`` parameter usage deletes all objects. 

Put the wtpkcs11ecp library into programm working directory.

```
python main.py --list-wallets
python main.py --show-wallet-info --wallet-id 0
python main.py --generate-key secp256 --wallet-id 0 --pin 12345678 --key-id my_bitcoin_masterkey_id --key-label my_secure_bitcoin_masterkey
python main.py --generate-key secp256 --wallet-id 0 --pin 12345678 --key-id my_eth_key_masterkey_id --key-label my_shared_eth_masterkey --get-mnemonic
python main.py --generate-key ed25519 --wallet-id 0 --pin 12345678 --key-id my_sol_key_masterkey_id --key-label my_secure_sol_masterkey
python main.py --import-key "24 words mnemonic phrase" --wallet-id 0 --pin 12345678 --key-id my_imported_eth_masterkey_id --key-label my_imported_eth_masterkey
python main.py --list-keys --wallet-id 0 --pin 12345678
python main.py --delete-key --key-number 1 --wallet-id 0 --pin 12345678
python main.py --delete-key --force --wallet-id 0 --pin 12345678
python main.py --change-pin --wallet-id 0 --pin 12345678 --new-pin 62434761
```
