# Block Affine Cipher Encryption and Decryption scripts 

## How to run
This project has been tested to work with python 3.7. The same version as default in the UAH CS
Linux computer labs. No libraries external to python have been used.

In order to run the encryption and decryption programs, simply execute the python scripts.

**NOTE:** The encryption program will clean your input file in a very particular way. Only 
values in the range of A to Z will be accepted. If you have text outside of that range in
the input file, you will receive a warning that your input file is being cleaned.

Here are some examples of clean input:

"THISISASECRET"
"FOOBAR"
"BLOCKAFFINE"

Illegal characters will be stripped from the input and fed to the encryptor.

"This Is A, Secret" yields "TIAS" before encryption.
"THIS IS A, SECRET" yields "THISISASECRET" before encryption.
"THIS IS A,
SECRET" yields "THISISASECRET" before encryption.

### ENCRYPTING
Put your secret message into a file labeled `plaintext.txt`, and execute the following command.

```
python encrypt.py
```

Follow the prompts entering your modulo multiplier and offset for use in the cipher until you get
a system prompt.

This will generate an encrypted text file called `ciphertext.txt`

### DECRYPTING
In order to decrypt `ciphertext.txt`, execute the following command.

```
python decrypt.py
```

Follow the prompts entering your modulo multiplier and offset used earlier until you get
a system prompt.

This will create a file called `finalplaintextoutput.txt` containing the secret message.
