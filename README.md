# vervet

A simple CLI tool for securely performing common Vault unseal key operations. Unseal keys are secured by private keys that are stored in hardware via the YubiKey OpenPGP application. Vervet streamlines Vault unseal key decryption and common unseal key workflows into single commands for ease of use. Yubico YubiKeys ensure that private keys used to decrypt Vault unseal keys are stored in hardware and non-exportable. Vervet is designed for Vault key officers responsible for managing unseal and recovery keys.

YubiKeys 5 series and above implement the [OpenPGP application by emulating an ISO-compliant smart card](https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf). This allows vervet to use standard APDU commands to interact with the OpenPGP application. Vervet currently only supports Yubico YubiKeys and will ignore other smart card manufacturers. At this time, OpenPGP management operations such as key generation, key export, and PIN/PUK changes must take via other utility. [GNU Privacy Guard](https://github.com/gpg/gnupg) offers full support for the OpenPGP application on ISO smart cards. 

Please reference [Dr. Duh's YubiKey Guide](https://github.com/drduh/YubiKey-Guide) for additional information on securely generating, handling, and storing PGP keys. 

## Features

- Written in uncomplicated Go (Golang)
- Simplifies common Vault unseal key workflows
- Provides a central location for securely storing Vault unseal keys
- Enables non-exportable hardware storage for PGP keys that encrypt unseal keys
- [Easy to use](https://github.com/onryo/vervet#usage)
- Works on Mac, Linux and (maybe) Windows

## Installation

```bash
$ git clone git@github.com:onryo/vervet.git
$ cd vervet
$ make install
```

## Usage

### Commands:

```
generate-root     Generate Vault root token
help              Help about any command
list              List connected YubiKeys and configured Vault clusters
show              Show details of YubiKeys and Vault clusters
unseal            Unseal Vault by server or cluster
```

### Configuration

The default vervet configuration file location is `~/.vervet/vervet.hcl`. The configuration file can be overridden at runtime with the `--config` flag. Keys can be specified directly in the configuration file using the `keys` attribute. Alternatively, keys can be placed in a separate file and linked via the `key_file` attribute. Vervet will open key files relative to the `~/.vervet` directory. Keys located in a seprate key file should be base64 encoded and new line delimited. Any duplicate unseal keys will be automatically deduplicated. 

```hcl
cluster "us-west" {
    servers = [
        "https://prod-vault-01.example.local:8200",
        "https://prod-vault-02.example.local:8200",
        "https://prod-vault-03.example.local:8200"
    ]
    keys = [
        "base64-encoded Vault unseal key"
    ]
    key_file = "us-west.pgp"
}

cluster "us-east" {
    [...]
}

```

### List clusters and YubiKeys

```bash
$ vervet list clusters    # list Vault clusters defined in vervet configuration
```

```bash
$ vervet list yubikeys    # list connected YubiKeys that support OpenPGP
```

### Unseal

```bash
$ vervet unseal cluster us-west    # decrypts unseal key(s) and unseals us-west Vault servers
```

To unseal an individual server:

```bash
$ vervet unseal server prod-vault-01.example.local key_file.pgp    # decrypt unseal key in key_file.pgp and unseal prod-vault-01
```

### Generate root token

```bash
$ vervet generate-root cluster us-west    # generate token for us-west Vault cluster
```

To target an individual server for root token generation:
```bash
$ vervet generate-root server prod-vault-01.example.local key_file.pgp    # decrypt unseal key in key_file.pgp and generate root token
```

## Contributing

#### Bug Reports & Feature Requests

Please use the [issue tracker](https://github.com/onryo/vervet/issues) to report any bugs or file feature requests.

#### Developing

PRs are welcome. To begin developing, do this:

```bash
$ git clone git@github.com:onryo/vervet.git
$ cd vervet
$ make
$ ./bin/vervet
```

## Acknowledgements

Vervet would not be possible without the following projects and resources.

- [HashiCorp Vault](https://vaultproject.io)
- [ebfe/scard](https://github.com/ebfe/scard) - Go bindings to the PC/SC API
- [Go Cryptography](https://pkg.go.dev/golang.org/x/crypto)
- [Go Ethereum](https://github.com/ethereum/go-ethereum)
- [Cobra](https://github.com/spf13/cobra)
- [Viper](https://github.com/spf13/viper)
- [Functional Specification of the OpenPGP application on ISO Smart Card Operating Systems](https://gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf)
- [RFC 4880](https://tools.ietf.org/html/rfc4880) - OpenPGP Message Format
- [joe](https://github.com/karan/joe) - README file inspiration
- [Dr. Duh's YubiKey Guide](https://github.com/drduh/YubiKey-Guide)
