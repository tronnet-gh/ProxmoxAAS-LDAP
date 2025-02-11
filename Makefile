.PHONY: build test clean dev-init dev-reinit

build: clean
	@echo "======================== Building Binary ======================="
	CGO_ENABLED=0 go build -ldflags="-s -w" -v -o dist/ .

test: dev-reinit
	@echo "======================== Running Tests ========================="
	go test -v -cover -coverpkg=./app/ -coverprofile coverage ./test/
	@echo "======================= Coverage Report ========================"
	go tool cover -func=coverage
	@rm -f coverage

clean:
	@echo "======================== Cleaning Project ======================"
	go clean
	rm -f dist/*

dev-init:
	@cd scripts; make dev-init

dev-reinit:
	@cd scripts; make dev-reinit