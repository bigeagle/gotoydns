all:
	go build gotoydns.go
install:
	go install github.com/bigeagle/gotoydns
fmt:
	gofmt -tabs=false -tabwidth=4 -w .
