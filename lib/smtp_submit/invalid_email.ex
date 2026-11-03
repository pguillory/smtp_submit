defmodule SMTPSubmit.InvalidEmail do
  @moduledoc """
  An email or envelope the library refuses to build or send. Nothing was sent.

  * `reason` - what is wrong; see the table below
  * `field` - where: `:from`, `:to`, `:cc`, `:bcc`, `:recipients`, `:subject`,
    `:text`, `:html`, `:attachments`, `:message`, `:headers`, or the name
    (a string) of a valid extra header whose value is refused

  | reason | meaning |
  | --- | --- |
  | `:invalid_address` | not a supported address (see the README) |
  | `:invalid_display_name` | not a string, invalid UTF-8 or has a control character |
  | `:invalid_subject` | not a string, invalid UTF-8 or has a control character |
  | `:missing_body` | neither `text` nor `html` is set |
  | `:invalid_body` | a body that is not valid UTF-8 |
  | `:invalid_attachment` | a bad filename, content type or data |
  | `:invalid_header_name` | not a valid field name |
  | `:reserved_header` | a field the builder writes itself |
  | `:duplicate_header` | a second Message-ID, In-Reply-To or References |
  | `:invalid_header_value` | a value the field's grammar doesn't allow, or too long for a line |
  | `:no_recipients` | an empty envelope |
  | `:invalid_message` | message text that isn't 7-bit with CRLF lines of at most 998 bytes |

  The message never includes the rejected value, so it is safe to log.
  """

  defexception [:reason, :field]

  @type t :: %__MODULE__{reason: atom(), field: atom() | String.t()}

  @impl true
  def message(%__MODULE__{reason: reason, field: field}) do
    "invalid email: #{reason} (#{field})"
  end
end
