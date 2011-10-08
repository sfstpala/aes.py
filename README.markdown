# aes.py

Based on parts of the SlowAES project, this module
lets you encrypt arbitrary python objects with AES256
in CBC mode.

http://code.google.com/p/slowaes/

The AES class is forked from the SlowAES project, and
completely refactored for pep8 compliance. I've thrown
out SlowAES's CBC Mode of Operation and written it from
scratch, to make it more readable and much shorter.

http://en.wikipedia.org/wiki/Block_cipher_modes_of_operation#Cipher-block_chaining_.28CBC.29

Additionally, this module has encrypt() and decrypt()
functions that incorporate all aspects of good symmetric
encryption:

 - Authentication (via sha256 hmac)
 - Integrity (via sha256)
 - Key stretching (salted, iterated sha256)
 - Nice encoding

http://en.wikipedia.org/wiki/HMAC
http://en.wikipedia.org/wiki/Key_stretching

You can call `encrypt()` with just two arguments:

 - `data`, any python objects that can be pickled
 - `passphrase`, a password of any length that is used to generate the actual encryption key

Additionally, you can provide two arguments:

 - `iterations`, the number of iterations of sha256 for the key derivation
 - `salt_length`, the size of the salt used for key derivation

The output of this function will be base64 string wrapped to 64 characters per line.

Decrypting the data is done by calling

    decrypt(data, passphrase)

And it returns the original python object.
