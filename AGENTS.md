# smtp_submit

An open source Elixir library: a hardened SMTP submission client over gen_smtp, an
RFC-conforming MIME builder and a loopback fake SMTP server. MIT licensed.

## This repository is public

Everything here is published: code, docs, tests, test data, commit messages and branch
names. Never put in any of them:

- secrets of any kind (keys, tokens, passwords, account IDs), even expired. The keys in
  `priv/fake_tls` and `test/fixtures/wrong_host_tls` are synthetic and public on purpose;
  nothing else is;
- internal or proprietary information about any company, product, customer or person,
  including private repository names, internal names, paths and hostnames;
- real email addresses, real mail or other personal data. Test data is synthetic:
  `example.com`, `example.net` and `example.test` addresses and made-up content.

Write docs and commit messages for an outside reader. Don't explain a change by some
application's needs; explain the behavior. Before every push, scan the diff and the
new commits for the above.

## API

The public API is what `README.md` and the `@doc`s document: `SMTPSubmit`,
`SMTPSubmit.Email`, `SMTPSubmit.Error`, `SMTPSubmit.InvalidEmail` and
`SMTPSubmit.FakeServer`. `SMTPSubmit.Worker`, `SMTPSubmit.Email.Header` and
`SMTPSubmit.FakeServer.Peer` are internal. A change to the API is a design
decision: keep it small, document it in the README, test it, and bump the version
(CHANGELOG, `mix.exs`, a `vX.Y.Z` tag).

Behavior that must hold:

- Use the unmodified gen_smtp client through `open/1`, `deliver/2` and `close/1` only.
  Pass the full TLS policy in both modes: `sockopts` for implicit TLS, `tls_options`
  for STARTTLS.
- Only a well-formed 4xx or 5xx reply during delivery is a definite refusal. Every
  other failure after open has an unknown outcome. Acceptance is latched before
  cleanup.
- Never log, and never put in an error, server text, hosts, credentials, envelope
  addresses or message data. The worker logs nothing at all.
- The builder follows the RFCs (5322, 2045 to 2047, 2183, 2231). It validates up front,
  and never writes a line over 998 bytes. Header lines fold toward 76 characters, and
  a line holding an encoded word never exceeds it.

## Code

- Stock `mix format`. `mix compile --warnings-as-errors` and `mix test` pass before
  every commit. No hosted CI: tests run locally.
- Simplicity first, and few dependencies, each justified in `mix.exs`. Today:
  `gen_smtp`.
- `def ... do ... end` for every function, never the keyword `do:` form. One alias per
  line, never grouped.
- Expected failures are returned as values (`{:error, %InvalidEmail{}}`,
  `{:error, %Error{}}`), never thrown or raised. Raising is for caller bugs, such as a
  config without its required keys. A `try`, `rescue` or `catch` is rare and has a
  comment naming its reason. One allowed exception: catching failures of code outside
  the library's control, such as gen_smtp raising on a malformed server reply, and
  turning them into errors without their contents.
- Normal commits only: no amend, rebase or force-push on `main`.

## Tests

- One layer per test, through the module's public interface, with the module under
  test imported. No peeking at internals, and no planting state the API can't produce.
  The documented `:client` config key is the seam for behavior gen_smtp can't be made
  to show over a socket (a close that never returns).
- Async by default. A module that isn't async names its one reason. No `capture_log`
  in async tests.
- Tests talk only to `SMTPSubmit.FakeServer` or hand-rolled peers bound to 127.0.0.1.
  Never contact a real mail server or send real mail.
- Tests may feed malformed or hostile server replies through the fake's scripts. The
  server is external input, so that is the library's real job, not planted state.
- Deadline tests are allowed: phase deadlines are a feature of this library. Use the
  fake's `:stall` and deadlines of a second or two, never sleeps.
