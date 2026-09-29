# TLS fixtures

Self-signed CA certificates used to test bundle loading in `src/tls.rs`. Public
certificates only, no private keys: the keys were generated in a scratch directory and
discarded, and nothing here is trusted by anything.

| File | Contents |
|---|---|
| `test-ca.pem` | one CA certificate |
| `test-ca-bundle.pem` | two, to check that a bundle loads every certificate in it |
| `refused.pem` | one `CERTIFICATE` block holding `hello world`: it parses, and the TLS backend refuses it when a client is built |

Parsing does not check validity dates, so these do not need refreshing. They are valid for
20 years regardless.

To regenerate:

```sh
openssl req -x509 -newkey rsa:2048 -keyout /tmp/k.pem -out test-ca.pem -days 7300 -nodes \
    -subj "/CN=waharoa test CA (fixture, not trusted anywhere)" \
    -addext "basicConstraints=critical,CA:TRUE"
```
