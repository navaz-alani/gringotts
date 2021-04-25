GC=go
SRCS=$(wildcard *.go)
EXEC=gringotts
TST_FILES=test

$(EXEC): $(SRCS)
	$(GC) build

.PHONY: clean tidy

tidy:
	go mod tidy
	go fmt ./...

clean:
	rm -rf $(EXEC)      # remove executable
	rm -rf $(TST_FILES) # remove test vault files
