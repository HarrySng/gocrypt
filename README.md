# Rudimentary Encryption Service in Go

## Encrypt/Decrypt a file with a master key for secure storage of electronic data

Encryption is done using an Advanced Symmetric-key Encryption (ASE) algorithm established in 2001 by U.S. National Institute of Standards and Technology (NIST) for the encryption of electronic data. The details of the algorithm can be found in this web.archive document [Federal Information Processing Standards Publication 197](https://web.archive.org/web/20170312045558/http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf) 

The algorithm was borrowed from package [crypto](https://golang.org/pkg/crypto/)

```go
import "crypto/aes"
```

## How to Use

### To Encrypt a File

Samplefile.txt contains the data you wish to encrypt.

```bash
encryptor.go /path/to/Samplefile.txt master_key
```

This will generate a new file in the current directory named Samplefile_yyyymmddhhmmss.enc which is the encrypted file.

### To Decrypt a File

Samplefile.enc contains the data you wish to decrypt.

```bash
encryptor.go /path/to/Samplefile.enc master_key
```

This will generate a new file in the current directory named Samplefile_yyyymmddhhmmss.txt which will contain the unencrypted data given that the same master_key is provided to decrypt the file as was used to encrypt it.
