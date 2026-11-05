# Changelog

## 0.2.0

- `SMTPSubmit.Error` has `auth_reply_codes`: for `:auth_failed`, the reply code of
  each refused AUTH attempt, in order, so a caller can tell a refused password
  (535) from other AUTH failures. `reply_code` is now set for `:auth_failed` to the
  last of them, and the error message shows it ("(reply 535)").

## 0.1.0

First release: `SMTPSubmit.send/4` and `SMTPSubmit.deliver/2` over gen_smtp 1.3 with
strict TLS, mandatory STARTTLS, phase deadlines and outcome-unknown errors;
`SMTPSubmit.Email` for building RFC 5322 MIME messages; and `SMTPSubmit.FakeServer`
for tests.
