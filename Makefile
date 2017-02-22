GO ?= go

build:
	glide update
	$(GO) build $(BUILD_OPTS) -v -i -o target/keil

dist: build
	strip target/keil

clean:
	-rm target/keil

