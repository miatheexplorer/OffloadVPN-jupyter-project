P4C ?= p4c
P4SRC = Offload.p4
BUILD_DIR = build
P4JSON = $(BUILD_DIR)/Offload.json
P4INFO = $(BUILD_DIR)/Offload.p4info.txt

.PHONY: all build controller clean

all: build

build:
	mkdir -p $(BUILD_DIR) logs
	$(P4C) --target bmv2 --arch v1model \
		-o $(P4JSON) \
		--p4runtime-files $(P4INFO) \
		$(P4SRC)
	@echo "[OK] Built: $(P4JSON) and $(P4INFO)"

controller:
	sudo -E python3 p4runtime_controller.py \
		--p4info $(P4INFO) \
		--bmv2-json $(P4JSON)

clean:
	rm -rf $(BUILD_DIR) logs