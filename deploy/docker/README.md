# ntwire Docker Compose example

This example runs an `ntwire-server` and a private HTTP echo service. It is a
starting point for local testing, not a production configuration.

## Before starting

1. Create `keys/` and add the public SSH keys that may authenticate:

   ```sh
   mkdir -p keys
   cp ~/.ntwire/id_ed25519.pub keys/
   ```

2. Review `ntwire.yaml`. In particular, replace `host.docker.internal:51820`
   with the host name or IP clients can reach, and replace the example tunnel
   with only the targets you intend to grant.

## Run and verify

From this directory, build and start the stack:

```sh
docker compose up --build -d
docker compose ps
docker compose logs -f ntwire-server
```

Connect with a client using `https://localhost:8443` (or the published host
name). The sample `example` tunnel reaches the Compose-only HTTP echo service.
Inspect the server logs before diagnosing a connection failure.

Stop the stack when finished:

```sh
docker compose down
```

Keep `keys/` out of source control, and never commit private keys or production
credentials. For production deployment,
TLS, OIDC, and relay guidance, see [docs/DEPLOYMENT.md](../../docs/DEPLOYMENT.md)
and [docs/CONFIGURATION.md](../../docs/CONFIGURATION.md).
