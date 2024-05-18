# Openfire Password Decryptor

This Python script is used to decrypt Openfire passwords. It uses the Blowfish algorithm for decryption.

## Install requirements

To install the dependencies, run the following command:
```bash
pip install -r requirements.txt
```

## Usage
To use the script, run the following command:
```bash
python main.py -p <encrypted_password> -k <blowfish_key>
```

Where:

- `<encrypted_password>` is the encrypted Openfire password (found in app db in table [ofUser] column [encryptedPassword]).
- `<blowfish_key>` is the Blowfish key used for decryption (found in app db in table [ofProperty] column [propValue] where [name]='passwordKey)