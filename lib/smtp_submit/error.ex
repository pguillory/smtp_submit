defmodule SMTPSubmit.Error do
  @moduledoc """
  A safe SMTP failure. Messages never include server text, hosts, credentials
  or message data.

  * `code` - `:timeout`, `:network`, `:tls_failed`, `:tls_unavailable`,
    `:auth_failed`, `:auth_unavailable`, `:rejected`, `:protocol` or `:internal`
  * `stage` - `:open` (connect, greeting, EHLO, TLS and AUTH) or `:deliver`
    (MAIL, RCPT, DATA and the final acceptance). Nothing has been sent at
    `:open`, so a `:rejected` there (a refused greeting or STARTTLS) is final.
  * `reply_code` - the server's three-digit reply code, when there was one
  * `timeout_ms` - the deadline that expired, for `:timeout`
  * `outcome_unknown?` - the server may already have accepted the email, so it
    must never be resent automatically

  `:auth_failed` is generic: the dependency collapses every refused mechanism
  into one result without the reply code, so it is not evidence that the
  password was revoked. Only a well-formed 4xx or 5xx reply during delivery is
  a definite refusal; every other delivery failure has an unknown outcome.
  """

  defexception [:code, :stage, :reply_code, :timeout_ms, outcome_unknown?: false]

  @type t :: %__MODULE__{
          code:
            :timeout
            | :network
            | :tls_failed
            | :tls_unavailable
            | :auth_failed
            | :auth_unavailable
            | :rejected
            | :protocol
            | :internal,
          stage: :open | :deliver,
          reply_code: 200..599 | nil,
          timeout_ms: pos_integer() | nil,
          outcome_unknown?: boolean()
        }

  @impl true
  def message(error) do
    reply = if error.reply_code, do: " (reply #{error.reply_code})", else: ""

    timeout =
      if error.timeout_ms,
        do: " after #{div(error.timeout_ms + 999, 1000)} seconds",
        else: ""

    ambiguity =
      if error.outcome_unknown?,
        do: ". The server may already have accepted the email; do not retry automatically.",
        else: ""

    "SMTP #{error.code} during #{error.stage}#{reply}#{timeout}#{ambiguity}"
  end
end
