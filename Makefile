default: mkbuilddir
	go build -o bin/vervet

mkbuilddir:
	if [ -d ./bin ]; then rm -rf bin; fi
	mkdir bin
