.PHONY: build
build:
	go get -u github.com/golang/dep/cmd/dep
	dep ensure
	gox -os="darwin linux windows" -arch="amd64"
	mv fireviz_darwin_amd64 fireviz_osx
	mv fireviz_linux_amd64 fireviz
	mv fireviz_windows_amd64.exe fireviz.exe
	zip -r fireviz.zip fireviz_osx fireviz fireviz.exe