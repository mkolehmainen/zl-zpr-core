OUT_DIR := build

.PHONY: all
all:
	mkdir -p $(OUT_DIR)
	go build -o $(OUT_DIR)/cactl cactl/*.go

.PHONY: clean
clean:
	rm -rf $(OUT_DIR)

