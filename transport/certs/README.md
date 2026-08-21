# Demo-only mTLS certificates

This directory contains OpenSSL profiles for a **local hackathon demo only**. The generated CA is
self-signed and is not production PKI. Do not install it in a system or browser trust store, reuse
its keys, or expose it outside the disposable local demo environment.

Generate a CA, Sentry server certificate, and primary-agent client certificate from the
`transport/` directory:

```sh
./scripts/generate_demo_certs.sh
```

The script writes the following git-ignored artifacts here:

- `demo-ca.crt` / `demo-ca.key` — local demo trust anchor and private key
- `demo-server.crt` / `demo-server.key` — server identity for `sentry.local` and localhost
- `demo-client.crt` / `demo-client.key` — client identity for `primary-srv-01`

It refuses to overwrite an existing set. Pass `--force` only when intentionally rotating the
local demo identities. Private keys are created with owner-only permissions.

Certificates authenticate peers; they do not by themselves enforce TLS 1.3 or outbound-only
connectivity. Those controls belong in the future client/server network configuration. The primary
agent's verified client-certificate identity is authoritative; a JSON `agent_id` is not.
