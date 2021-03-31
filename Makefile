default: mkbuilddir
	go build -o bin/vervet

install:
	go install

mkbuilddir:
	if [ -d ./bin ]; then rm -rf bin; fi
	mkdir bin
