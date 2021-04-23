GC=go
SRCS=$(wildcard *.go)
EXEC=vault
TST_FILES=test

$(EXEC): $(SRCS)
	$(GC) build

.PHONY: clean

clean:
	rm -rf $(EXEC)      # remove executable
	rm -rf $(TST_FILES) # remove test vault files
