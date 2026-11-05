# SMTPSubmit

A hardened SMTP submission client for Elixir: one authenticated message per call,
over verified TLS, with deadlines and an honest answer when the outcome is unknown.
It includes a MIME message builder that follows the email RFCs, and a loopback fake
SMTP server for tests.

The SMTP protocol work is done by the unmodified [gen_smtp](https://hex.pm/packages/gen_smtp)
client. SMTPSubmit wraps it with what a submission client needs and gen_smtp leaves
to the caller:

- **Strict TLS in both modes.** It verifies the peer, allows TLS 1.2 and 1.3 only,
  checks the hostname, sends SNI and uses the OS CA store. gen_smtp's defaults allow
  TLS 1.0 and verify at depth 0, which rejects every real certificate chain with an
  intermediate CA. That depth applies to implicit TLS and to the STARTTLS upgrade.
- **Mandatory STARTTLS.** Off port 465, a server that doesn't offer STARTTLS fails
  before credentials are sent. There is no plaintext mode.
- **Deadlines.** Each phase of a send has a deadline. The connection lives in a
  short-lived worker that is killed when a deadline passes or the caller dies, so no
  work outlives the call.
- **Outcome unknown.** Only a well-formed 4xx or 5xx reply during delivery is a
  definite refusal. Any other failure after the message was sent (a timeout, a
  dropped connection, a reply gen_smtp can't parse) may have been accepted, and says
  so, so it is never resent blindly.
- **Safe errors.** Errors carry fixed codes and numbers only: no server text, hosts,
  addresses or credentials. The worker logs nothing.

## Installation

SMTPSubmit isn't on Hex yet. Add it as a git dependency pinned to a tag:

```elixir
def deps do
  [
    {:smtp_submit, git: "https://github.com/pguillory/smtp_submit.git", tag: "v0.2.0"}
  ]
end
```

Requires Elixir 1.18 or later. Its one dependency is `gen_smtp` 1.3.x, which brings
`ranch`. The client was tested against gen_smtp 1.3.0.

## Example

```elixir
config = %{
  host: "smtp.example.com",
  port: 587,
  username: "person@example.com",
  password: password
}

email = %SMTPSubmit.Email{
  from: {"Pat Example", "person@example.com"},
  to: ["friend@example.net"],
  bcc: ["archive@example.com"],
  subject: "Lunch?",
  text: "Thursday at noon?",
  html: "<p>Thursday at noon?</p>"
}

case SMTPSubmit.deliver(config, email) do
  :ok -> :sent
  {:error, %SMTPSubmit.Error{outcome_unknown?: true}} -> :maybe_sent_do_not_retry
  {:error, %SMTPSubmit.Error{} = error} -> {:failed, Exception.message(error)}
  {:error, %SMTPSubmit.InvalidEmail{} = error} -> {:invalid, error.reason}
end
```

## API

### Sending

- `SMTPSubmit.deliver(config, email)` builds an `SMTPSubmit.Email` and sends it from
  its From address to every To, Cc and Bcc address (exact duplicates once). Bcc is
  never written to the message.
- `SMTPSubmit.send(config, from, recipients, message)` sends finished RFC 5322 text
  to an explicit envelope. The text must be 7-bit with CRLF line endings, no NUL
  and no line over 998 bytes. One trailing CRLF is dropped, because the DATA terminator
  supplies it.

Both return one of three outcomes:

- `:ok`: the server accepted the message.
- `{:error, %SMTPSubmit.Error{outcome_unknown?: true}}`: the server **may have
  accepted** the message. Don't resend it automatically.
- `{:error, %SMTPSubmit.Error{}}` (with `outcome_unknown?: false`) or
  `{:error, %SMTPSubmit.InvalidEmail{}}`: it was not delivered.
  `InvalidEmail` means nothing was sent and no connection was opened.

`SMTPSubmit.Error` has a `code` (`:timeout`, `:network`, `:tls_failed`,
`:tls_unavailable`, `:auth_failed`, `:auth_unavailable`, `:rejected`, `:protocol` or
`:internal`), a `stage` (`:open` covers connect, greeting, EHLO, STARTTLS and AUTH,
before anything was sent; `:deliver` covers MAIL through the final reply), the
server's `reply_code` when there was one, the expired `timeout_ms`, and
`outcome_unknown?`. An `:auth_failed` error also has `auth_reply_codes`, the codes
of the AUTH refusals observed, one per refused mechanism in the order tried, and
its `reply_code` is the last of them. A 535 ("authentication credentials invalid",
RFC 4954) means the server refused the credentials themselves.

### Config

A map:

| Key | Meaning | Default |
| --- | --- | --- |
| `:host`, `:port` | the submission server | required |
| `:username`, `:password` | credentials; AUTH is always required | required |
| `:tls` | `:implicit` (TLS from the first byte) or `:starttls` | `:implicit` on port 465, else `:starttls` |
| `:cacertfile` | a CA file to trust instead of the OS store | OS store |
| `:hostname` | the EHLO name, a plain domain or address literal | gen_smtp's guess at this host's FQDN |
| `:open_timeout` | connect, greeting, EHLO, STARTTLS and AUTH, in ms | 120 000 |
| `:deliver_timeout` | MAIL through the final reply, in ms | 240 000 |
| `:cleanup_timeout` | QUIT and close, in ms | 5 000 |
| `:connect_timeout` | the TCP connect and, for implicit TLS, the handshake (inside open), in ms | 15 000 |
| `:client` | a module with `gen_smtp_client`'s `open/1`, `deliver/2`, `close/1`, for tests and wrappers | `:gen_smtp_client` |

A config without the required keys raises `ArgumentError` with fixed text that never
shows the password.

### Building messages

`SMTPSubmit.Email.build(email, opts)` returns `{:ok, message}` or
`{:error, %SMTPSubmit.InvalidEmail{}}`. Pass `bcc_header: true` to keep a Bcc header,
for a draft saved to a mailbox. Never send a message built that way.

`%SMTPSubmit.Email{}` fields:

- `from`: the sender (required)
- `to`, `cc`, `bcc`: lists of addresses
- `subject`: a string
- `text`, `html`: the bodies; at least one is required
- `attachments`: a list of `%{filename:, content_type:, data:}`
- `headers`: extra `{name, value}` fields

An address is `"person@example.com"` or `{"Display Name", "person@example.com"}`.

`SMTPSubmit.Email.valid_address?(address)` says whether an address is in the
supported subset (below). `SMTPSubmit.Email.new_message_id(address)` returns a fresh
`<random@domain>`. Pass it as a `{"Message-ID", id}` header when you need to know a
message's id before sending it.

What the builder writes:

- From, To, Cc (Bcc only on request), Subject, Date (RFC 5322 form, UTC),
  Message-ID, your extra fields, then MIME-Version and the content headers. Empty
  To and Cc are left out.
- Header lines fold at whitespace toward 76 characters (RFC 2047's limit for lines
  with encoded words, under RFC 5322's 78). A line with an encoded word always fits.
  A single token that can't be split (a long address, say) may run longer, but no
  line exceeds 998.
- Non-ASCII subjects and display names become RFC 2047 `B` encoded words of at most
  75 characters, which never split a UTF-8 character. So does ASCII text that looks
  like an encoded word. ASCII display names are quoted with `"` and `\` escaped.
- Bodies are UTF-8 with line endings normalized to CRLF, base64 in 76-column
  lines. Text plus HTML makes `multipart/alternative`. Attachments make
  `multipart/mixed` with the body first.
- Attachment filenames get an ASCII `filename="..."` fallback, plus RFC 2231
  `filename*` continuations when the name is not plain ASCII.

Validation happens first and returns `InvalidEmail` with a `reason` and `field`,
never the value:

- Addresses: a dot-atom local part (no leading, trailing or doubled dots), a domain
  of letters, digits and hyphens in dot-separated labels, at most 254 bytes.
- Display names, the subject and filenames: valid UTF-8 without control characters.
  Filenames are at most 255 bytes.
- Content types: `type/subtype` tokens, not `multipart/*` or `message/*`.
- Extra headers: valid field names. From, To, Cc, Bcc, Subject, Date, MIME-Version
  and `Content-*` are written by the builder and refused. `Message-ID` must be a
  strict `<dot-atom@dot-atom-or-[literal]>`. `In-Reply-To` and `References` are
  space-separated msg-ids, checked loosely because they echo ids from received mail,
  which can use obsolete forms. Each of those three may appear once. Every other
  field is ASCII text, folded at spaces.

## Fake server

`SMTPSubmit.FakeServer` is a real SMTP submission server on 127.0.0.1, for tests and
local development. It parses the server side itself: greeting, EHLO, STARTTLS,
AUTH LOGIN and PLAIN, MAIL, RCPT, DATA with dot-unstuffing, RSET, NOOP and QUIT.

```elixir
server = start_supervised!({SMTPSubmit.FakeServer, username: "u", password: "p"})
%{host: host, port: port, cacertfile: ca} = SMTPSubmit.FakeServer.endpoint(server)

:ok =
  SMTPSubmit.deliver(
    %{host: host, port: port, cacertfile: ca, username: "u", password: "p"},
    email
  )

[%{from: _, recipients: _, data: _}] = SMTPSubmit.FakeServer.messages(server)
```

- `start_link(opts)` takes `:tls` (`:starttls` by default, `:implicit` or `:none`),
  `:username`, `:password`, `:auth_mechanisms`, `:certfile`/`:keyfile`/`:chainfile`,
  `:name` and `:observer` (a pid sent `{:smtp_fake, server, event}` per command).
- `endpoint(server)` returns `%{host: "localhost", port:, cacertfile:}`.
- `ca_file()` returns the synthetic CA that signs the default identity.
- `commands(server)` lists command records without AUTH payloads, and
  `messages(server)` lists the accepted messages.
- `script(server, kind, action)` makes the next command of a kind reply with
  `{:reply, text}`, `:stall` or `:close`. The kinds are `:greeting`, `:ehlo`,
  `:starttls`, `:auth`, `:mail`, `:rcpt`, `:data`, `:data_end` and `:quit`.

Its TLS identity in `priv/fake_tls` is synthetic and public; see the README there.

## Limitations

- No per-command timeouts. gen_smtp reads with a fixed 20-minute timeout, and its
  STARTTLS handshake has a fixed 5 s limit, so the phase deadlines are what bound a
  slow server.
- No SIZE check. An oversized message is refused with the server's 552 after the
  whole body was sent.
- There is no choice of AUTH mechanism: gen_smtp tries CRAM-MD5, LOGIN, PLAIN and
  XOAUTH2 in turn, among those the server offers. `auth_reply_codes` comes from
  gen_smtp's trace callback, which doesn't report XOAUTH2's reply, so a refusal
  there adds no code. The traces are gen_smtp 1.3's; a release that changed them
  would leave the list empty.
- With implicit TLS, OTP sends an IP-literal host as SNI, which RFC 6066 disallows.
  The certificate is still checked against the IP. Hostnames are unaffected.
- No SMTPUTF8: addresses are ASCII. `send/4` takes 7-bit messages only, though
  servers often accept 8BITMIME. Quoted local parts and domain literals aren't
  supported in addresses, and extra header values must be ASCII.

## License

MIT. See [LICENSE](LICENSE).
