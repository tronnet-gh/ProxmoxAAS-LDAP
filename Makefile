build: clean
	CGO_ENABLED=0 go build -ldflags="-s -w" -o dist/ .

test: clean
	go run .

clean:
	go clean
	rm -f dist/*