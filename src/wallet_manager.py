from web3 import Web3
from web3.middleware import geth_poa_middleware
from eth_account import Account
from decimal import Decimal
from loguru import logger
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import gspread
from google.oauth2.service_account import Credentials

Account.enable_unaudited_hdwallet_features()

class WalletManager():
    def __init__(self, provider_url: str, sheet_name: str, email: str):
        self.w3 = Web3(Web3.HTTPProvider(provider_url))
        self.sheet_name = sheet_name
        self.gc = self.authenticate_google_sheets()
        self.sheet = self.get_or_create_sheet(sheet_name, email)

    def authenticate_google_sheets(self):
        creds = Credentials.from_service_account_file(
            './credentials.json',
            scopes=["https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/drive"]
        )
        gc = gspread.authorize(creds)
        return gc

    def get_or_create_sheet(self, sheet_name: str, email: str):
        try:
            sheet = self.gc.open(sheet_name).sheet1
        except gspread.SpreadsheetNotFound:
            spreadsheet = self.gc.create(sheet_name)
            sheet = spreadsheet.sheet1
            spreadsheet.share(email, perm_type='user', role='writer')
        return sheet

    def save_wallet_to_sheet(self, public_key: str, encrypted_mnemonic: bytes):
        encrypted_mnemonic_str = encrypted_mnemonic.hex()
        self.sheet.append_row([public_key, encrypted_mnemonic_str])

    def retrieve_and_print_wallets(self, private_key: str):
        # Fetch all records
        records = self.sheet.get_all_records()
        all_data = list()
        for record in records:
            public_key = record['public_key']
            encrypted_mnemonic_str = record['encrypted_mnemonic']
            encrypted_mnemonic = bytes.fromhex(encrypted_mnemonic_str)

            # Decrypt the mnemonic using the private key
            decrypted_mnemonic = self.decrypt_text(encrypted_mnemonic, private_key)
            private_key_from_mnemonic = Account.from_mnemonic(decrypted_mnemonic)
            all_data.append((private_key_from_mnemonic, decrypted_mnemonic, public_key))
            logger.debug(f"Public Key: {public_key}")
            logger.debug(f"Private Key: {private_key_from_mnemonic}")
            logger.debug(f"Decrypted Mnemonic: {decrypted_mnemonic}")
        return all_data

    def get_random_wallet(self):
        return Account.create_with_mnemonic()

    def derive_shared_key(self, private_key: str):
        account = Account.from_key(private_key)
        private_key_bytes = account.key

        private_key_obj = ec.derive_private_key(
            int.from_bytes(private_key_bytes, byteorder='big'),
            ec.SECP256K1(),
            backend=default_backend()
        )
        public_key_obj = private_key_obj.public_key()
        return private_key_obj, public_key_obj

    def encrypt_text(self, text: str, private_key: str):
        private_key_obj, public_key_obj = self.derive_shared_key(private_key)
        shared_key = private_key_obj.exchange(ec.ECDH(), public_key_obj)
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        pad_length = 16 - (len(text) % 16)
        padded_text = text + chr(pad_length) * pad_length
        encrypted_text = encryptor.update(padded_text.encode('utf-8')) + encryptor.finalize()

        return iv + encrypted_text

    def decrypt_text(self, encrypted_text: bytes, private_key: str):
        private_key_obj, public_key_obj = self.derive_shared_key(private_key)
        shared_key = private_key_obj.exchange(ec.ECDH(), public_key_obj)
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)

        iv = encrypted_text[:16]
        ciphertext = encrypted_text[16:]

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_padded_text = decryptor.update(ciphertext) + decryptor.finalize()
        pad_length = ord(decrypted_padded_text[-1:])
        decrypted_text = decrypted_padded_text[:-pad_length].decode('utf-8')

        return decrypted_text
    
    def transfer(self, _from: str, _to: str, _amount_eth: Decimal, private_key: str):
        amount_wei = self.w3.to_wei(_amount_eth, "ether")
        nonce = self.w3.eth.get_transaction_count(_from)
        
        latest_block = self.w3.eth.get_block("latest")
        base_fee_per_gas = latest_block["baseFeePerGas"]

        max_priority_fee_per_gas = self.w3.to_wei(2, "gwei")
        max_fee_per_gas = base_fee_per_gas + max_priority_fee_per_gas

        tx = dict(
            nonce=nonce,
            to=_to,
            value=amount_wei,
            gas=21000,
            maxFeePerGas=max_fee_per_gas,
            maxPriorityFeePerGas=max_priority_fee_per_gas,
            chainId=self.w3.eth.chain_id,
            type=2,
        )

        signed_tx = self.w3.eth.account.sign_transaction(tx, private_key)
        tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        return tx_hash, receipt

    def check_balance(self, address: str):
        wei_balance = self.w3.eth.get_balance(address)
        eth_balance = self.w3.from_wei(wei_balance, "ether")
        return wei_balance, eth_balance

if __name__ == '__main__':
    provider_url = os.environ.get("PROVIDER_URL")
    sheet_name = os.environ.get("SHEET_NAME")
    email = os.environ.get("EMAIL")
    w = WalletManager(provider_url, sheet_name, email)
    address = os.environ.get("PUBLIC_ADDRESS")
    private_key = os.environ.get("PRIVATE_KEY")
    balance_threshold = Decimal(os.environ.get("BALANCE_THRESHOLD"))
    wei, eth = w.check_balance(address)
    logger.info(f"balance {eth=}")

    # Retrieve and print all wallets from Google Sheets
    all_data = w.retrieve_and_print_wallets(private_key)
    # print balances for all the keys
    for _, _, public_key in all_data:
        _, balance = w.check_balance(public_key)
        logger.debug(f"{public_key}: {balance}")


    if eth >= balance_threshold:
        # create a random wallet
        account, mnemonic = w.get_random_wallet()
        logger.info(f"New wallet private key (hex): {account.key.hex()}")
        logger.info(f"New wallet mnemonic: {mnemonic}")

        # Encrypt and then decrypt the mnemonic using the hybrid approach
        encrypted_mnemonic = w.encrypt_text(mnemonic, private_key)
        logger.info(f"Encrypted Mnemonic: {encrypted_mnemonic}")

        decrypted_mnemonic = w.decrypt_text(encrypted_mnemonic, private_key)
        logger.info(f"Decrypted Mnemonic: {decrypted_mnemonic}")

        assert mnemonic == decrypted_mnemonic

        # Save the encrypted mnemonic and public key to Google Sheets
        w.save_wallet_to_sheet(account.address, encrypted_mnemonic)

        # Transfer the balance - threshold to the new wallet
        amount_to_send = (eth - balance_threshold)
        tx_hash, receipt = w.transfer(address, account.address, amount_to_send, private_key)
        logger.info(f"Transfer successful: {tx_hash}")
