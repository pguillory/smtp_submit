# Fake server TLS identity

A throwaway identity for `SMTPSubmit.FakeServer`. It is not a real credential: the
private key is public on purpose. Trust the CA only in a client explicitly pointed at
it (`SMTPSubmit.FakeServer.ca_file/0`), never in an operating system store.

- `ca.pem`: a self-signed root, `CN=SMTPSubmit fake root CA - test only`
- `intermediate.pem`: signed by the root, `pathlen:0`. The fake sends it as its
  chain, so a client must verify past depth 0, as it must for real providers.
- `localhost.pem` and `localhost-key.pem`: the leaf, signed by the intermediate,
  with SANs `DNS:localhost` and `IP:127.0.0.1`

All RSA 2048 / SHA-256, valid for ten years from 2026-11-02. The CA keys were
discarded. `test/fixtures/wrong_host_tls` holds a leaf for `wrong.example.test`
signed by the same intermediate.

To regenerate, in an empty temporary directory, make the root with
`openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650` and extensions
`basicConstraints=critical,CA:TRUE` and `keyUsage=critical,keyCertSign,cRLSign`.
Make each other key and CSR with `openssl req -new -newkey rsa:2048 -nodes -sha256`
and sign it with `openssl x509 -req -days 3650 -sha256 -set_serial N -extfile EXT`.
The intermediate's extensions:

```text
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
```

The leaves':

```text
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
```

(`subjectAltName=DNS:wrong.example.test` for the wrong-host leaf.) Regenerate
both directories together.
