# Test fixtures, not secrets

These files only serve the end-to-end test of `klav-proxy` (`src/e2e_tests.rs`): a fake HTTPS upstream presents `leaf.der` for `upstream.test`, and the proxy under test trusts only `ca.der`, through a constructor that only test code can call. No release build reads them.

- `ca.der`: a self-signed P-256 CA, "klav-proxy test CA (fixture)".
- `leaf.der` and `leaf.key.der` (PKCS#8): its leaf for `upstream.test` and `metadata.test`, with `serverAuth`.

Both certificates are valid until 2126, so the test does not expire. They were made with `openssl` (`ecparam -name prime256v1`, `req -x509 -days 36500`, then `x509 -req` with the extensions above). Make new ones the same way if they ever need to change. Never use them for anything else.
