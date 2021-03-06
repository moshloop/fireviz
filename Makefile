.PHONY: build
build:
	go get -u github.com/golang/dep/cmd/dep
	dep ensure
	mkdir -p build
	gox -os="darwin linux windows" -arch="amd64"
	mkdir -p build/osx
	mkdir -p build/linux
	mkdir -p build/windows
	mv fireviz_darwin_amd64 build/osx/fireviz
	mv fireviz_linux_amd64 build/linux/fireviz
	mv fireviz_windows_amd64.exe build/windows/fireviz.exe
	cp README.md build/
	zip -r fireviz.zip build/*