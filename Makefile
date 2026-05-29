.PHONY: fmt check test clippy build release-check up curl-meta

fmt:
	cargo fmt --all --check

check:
	cargo check --workspace

test:
	cargo test --workspace

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

build:
	cargo build --release --bin opsgate-api

release-check: fmt check test clippy build
	git diff --check

up:
	docker compose up --build -d

curl-meta:
	curl -fsS http://localhost:9091/health
	curl -fsS http://localhost:9091/ready
	curl -fsS http://localhost:9091/.well-known/oauth-authorization-server
	curl -fsS http://localhost:9091/.well-known/oauth-protected-resource
	curl -fsS http://localhost:9091/.well-known/oauth-protected-resource/mcp
	curl -i -sS http://localhost:9091/mcp -X POST -H 'content-type: application/json' -d '{}'
	curl -i -sS http://localhost:9091/mcp/admin -X POST -H 'content-type: application/json' -d '{}'
