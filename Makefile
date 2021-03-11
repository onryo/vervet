default: mkbuilddir
	go build -o bin/vault-yubikey-pgp-unseal

mkbuilddir:
	if [ -d ./bin ]; then rm -rf bin; fi
	mkdir bin
