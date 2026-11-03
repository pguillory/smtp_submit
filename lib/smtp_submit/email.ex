defmodule SMTPSubmit.Email do
  @moduledoc """
  An email to build into an RFC 5322 MIME message.

  * `from` - the sender address (required)
  * `to`, `cc`, `bcc` - lists of addresses
  * `subject` - a string; default `""`
  * `text`, `html` - the bodies; at least one is required, and both make
    `multipart/alternative`
  * `attachments` - a list of `%{filename: String.t(), content_type: String.t(), data: binary()}`
  * `headers` - extra `{name, value}` header fields

  An address is `"person@example.com"` or `{"Display Name", "person@example.com"}`
  (a `nil` or `""` name means none).

  `build/2` validates everything first and returns `{:error,
  %SMTPSubmit.InvalidEmail{}}` for anything it can't write correctly. See the
  README for the exact rules.
  """

  alias SMTPSubmit.Email.Header
  alias SMTPSubmit.InvalidEmail

  defstruct from: nil,
            to: [],
            cc: [],
            bcc: [],
            subject: "",
            text: nil,
            html: nil,
            attachments: [],
            headers: []

  @type address :: String.t() | {String.t() | nil, String.t()}
  @type t :: %__MODULE__{
          from: address(),
          to: [address()],
          cc: [address()],
          bcc: [address()],
          subject: String.t(),
          text: String.t() | nil,
          html: String.t() | nil,
          attachments: [%{filename: String.t(), content_type: String.t(), data: binary()}],
          headers: [{String.t(), String.t()}]
        }

  @atext "[A-Za-z0-9!#$%&'*+\\-/=?^_`{|}~]+"
  @dot_atom "#{@atext}(?:\\.#{@atext})*"
  @label "[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
  @address Regex.compile!("\\A#{@dot_atom}@#{@label}(?:\\.#{@label})*\\z")
  @strict_message_id Regex.compile!("\\A<#{@dot_atom}@(?:#{@dot_atom}|\\[[!-Z^-~]*\\])>\\z")
  @max_address_bytes 254
  @max_filename_bytes 255
  @mime_token ~r/\A[!#$%&'*+.^_`|~0-9A-Za-z-]+\z/
  # Field names are printable ASCII except the colon (RFC 5322 ftext).
  @field_name ~r/\A[!-9;-~]+\z/
  @reserved_headers ["from", "to", "cc", "bcc", "subject", "date", "mime-version"]
  @message_id_headers ["message-id", "in-reply-to", "references"]

  @doc """
  Builds the message text. Returns `{:ok, binary}`, CRLF line endings, 7-bit,
  no line over 998 bytes, or `{:error, %SMTPSubmit.InvalidEmail{}}`. It doesn't
  end in CRLF unless the message is a single empty part (an empty body and no
  attachments), where it ends with the blank line after the headers.

  Options:

  * `:bcc_header` - write a Bcc header, for a draft saved to a mailbox;
    default false. A sent message must never carry one.
  """
  @spec build(t(), keyword()) :: {:ok, binary()} | {:error, InvalidEmail.t()}
  def build(%__MODULE__{} = email, opts \\ []) do
    with {:ok, from} <- mailbox(email.from, :from),
         {:ok, to} <- mailboxes(email.to, :to),
         {:ok, cc} <- mailboxes(email.cc, :cc),
         {:ok, bcc} <- mailboxes(email.bcc, :bcc),
         {:ok, subject} <- subject(email.subject),
         {:ok, extra} <- extra_headers(email.headers),
         {:ok, body_headers, body} <- body(email) do
      bcc = if Keyword.get(opts, :bcc_header, false), do: bcc, else: []
      message_id = extra[:message_id] || new_message_id(elem(from, 1))

      headers =
        [
          address_field("From", [from]),
          address_field("To", to),
          address_field("Cc", cc),
          address_field("Bcc", bcc),
          {:ok, subject},
          {:ok, "Date: " <> date(DateTime.utc_now())},
          Header.fold("Message-ID", [message_id])
        ] ++ extra.fields ++ [{:ok, "MIME-Version: 1.0"}] ++ Enum.map(body_headers, &{:ok, &1})

      case collect(headers, "headers") do
        {:ok, fields} -> {:ok, Enum.join(fields, "\r\n") <> "\r\n\r\n" <> body}
        {:error, _} = error -> error
      end
    end
  end

  @doc """
  A new random Message-ID, `<32 hex digits@domain>`, using the domain of
  `address`. Set it with a `{"Message-ID", id}` header to know the id of a
  message before sending it.
  """
  @spec new_message_id(String.t()) :: String.t()
  def new_message_id(address) do
    if not valid_address?(address), do: raise(ArgumentError, "not a supported email address")
    [_local, domain] = String.split(address, "@")
    "<" <> random_hex() <> "@" <> domain <> ">"
  end

  @doc false
  # The bare envelope addresses: sender and to ++ cc ++ bcc.
  def envelope(%__MODULE__{} = email) do
    with {:ok, {_name, from}} <- mailbox(email.from, :from),
         {:ok, to} <- mailboxes(email.to, :to),
         {:ok, cc} <- mailboxes(email.cc, :cc),
         {:ok, bcc} <- mailboxes(email.bcc, :bcc) do
      {:ok, from, Enum.map(to ++ cc ++ bcc, &elem(&1, 1))}
    end
  end

  @doc """
  Whether `address` is a bare address the library accepts: a dot-atom local
  part, a domain of dot-separated letter, digit and hyphen labels, at most
  254 bytes.
  """
  @spec valid_address?(term()) :: boolean()
  def valid_address?(address) do
    is_binary(address) and byte_size(address) <= @max_address_bytes and
      Regex.match?(@address, address)
  end

  defp invalid(reason, field) do
    {:error, %InvalidEmail{reason: reason, field: field}}
  end

  defp collect(results, field) do
    Enum.reduce_while(results, {:ok, []}, fn
      {:ok, nil}, acc -> {:cont, acc}
      {:ok, value}, {:ok, values} -> {:cont, {:ok, [value | values]}}
      {:error, _} = error, _acc -> {:halt, error}
      :error, _acc -> {:halt, invalid(:invalid_header_value, field)}
    end)
    |> case do
      {:ok, values} -> {:ok, Enum.reverse(values)}
      error -> error
    end
  end

  # Addresses

  defp mailboxes(list, field) when is_list(list) do
    list |> Enum.map(&mailbox(&1, field)) |> collect(field)
  end

  defp mailboxes(_list, field) do
    invalid(:invalid_address, field)
  end

  defp mailbox({name, address}, field) do
    cond do
      not valid_address?(address) -> invalid(:invalid_address, field)
      name in [nil, ""] -> {:ok, {nil, address}}
      header_text?(name) -> {:ok, {name, address}}
      true -> invalid(:invalid_display_name, field)
    end
  end

  defp mailbox(address, field) do
    mailbox({nil, address}, field)
  end

  # Mailboxes separated by commas, folding between and within them.
  defp address_field(_name, []) do
    {:ok, nil}
  end

  defp address_field(name, mailboxes) do
    last = length(mailboxes) - 1

    tokens =
      mailboxes
      |> Enum.with_index()
      |> Enum.flat_map(fn {mailbox, index} ->
        tokens = mailbox_tokens(mailbox)
        if index < last, do: List.update_at(tokens, -1, &(&1 <> ",")), else: tokens
      end)

    Header.fold(name, tokens)
  end

  defp mailbox_tokens({nil, address}) do
    [address]
  end

  defp mailbox_tokens({name, address}) do
    quoted = Header.quoted(name)

    # A quoted-string can't fold, so a long name goes out as encoded words.
    phrase =
      if Header.printable_ascii?(name) and byte_size(quoted) < 70,
        do: [quoted],
        else: Header.encoded_words(name)

    phrase ++ ["<" <> address <> ">"]
  end

  # Header text: valid UTF-8 with no control characters.
  defp header_text?(value) do
    is_binary(value) and String.valid?(value) and not Regex.match?(~r/[\x00-\x1f\x7f]/, value)
  end

  # Subject

  defp subject(subject) do
    if header_text?(subject) do
      tokens = Header.words(subject)

      # Text that looks like an encoded word must be encoded so a reader
      # doesn't decode it (RFC 2047 section 5).
      encode? =
        not Header.printable_ascii?(subject) or
          Regex.match?(~r/=\?[^?]*\?[bBqQ]\?[^?]*\?=/, subject) or
          Enum.any?(tokens, &(byte_size(&1) > 900))

      tokens = if encode?, do: Header.encoded_words(subject), else: tokens
      fold_or_invalid("Subject", tokens)
    else
      invalid(:invalid_subject, :subject)
    end
  end

  # Extra headers

  defp extra_headers(headers) when is_list(headers) do
    Enum.reduce_while(headers, {:ok, %{fields: [], message_id: nil, seen: []}}, fn
      {name, value}, {:ok, acc} when is_binary(name) and is_binary(value) ->
        case extra_header(name, value, acc) do
          {:ok, acc} -> {:cont, {:ok, acc}}
          error -> {:halt, error}
        end

      {name, _value}, _acc when is_binary(name) ->
        {:halt, invalid(:invalid_header_value, :headers)}

      _header, _acc ->
        {:halt, invalid(:invalid_header_name, :headers)}
    end)
    |> case do
      {:ok, acc} -> {:ok, %{acc | fields: Enum.reverse(acc.fields)}}
      error -> error
    end
  end

  defp extra_headers(_headers) do
    invalid(:invalid_header_name, :headers)
  end

  defp extra_header(name, value, acc) do
    key = String.downcase(name)

    cond do
      # An invalid name is reported as :headers, never itself: it could carry line
      # breaks or private text into a log.
      not Regex.match?(@field_name, name) ->
        invalid(:invalid_header_name, :headers)

      key in @reserved_headers or String.starts_with?(key, "content-") ->
        invalid(:reserved_header, name)

      key in acc.seen ->
        invalid(:duplicate_header, name)

      key == "message-id" ->
        if Regex.match?(@strict_message_id, value),
          do: {:ok, %{acc | message_id: value, seen: [key | acc.seen]}},
          else: invalid(:invalid_header_value, name)

      key in @message_id_headers ->
        with {:ok, ids} <- message_ids(value, name),
             {:ok, field} <- fold_or_invalid(name, ids) do
          {:ok, %{acc | fields: [{:ok, field} | acc.fields], seen: [key | acc.seen]}}
        end

      Enum.all?(:binary.bin_to_list(value), &(&1 == ?\t or &1 in 0x20..0x7E)) ->
        with {:ok, field} <- fold_or_invalid(name, Header.words(value)) do
          {:ok, %{acc | fields: [{:ok, field} | acc.fields]}}
        end

      true ->
        invalid(:invalid_header_value, name)
    end
  end

  # In-Reply-To and References echo ids from received mail, which may use the
  # obsolete forms RFC 5322 section 4.5.4 still parses (a quoted local part,
  # say), so they are checked loosely: <...> around printable ASCII without
  # whitespace or angle brackets, with one inner @.
  defp message_ids(value, name) do
    ids = String.split(value, [" ", "\t"], trim: true)

    if ids != [] and Enum.all?(ids, &loose_message_id?/1),
      do: {:ok, ids},
      else: invalid(:invalid_header_value, name)
  end

  defp loose_message_id?(id) do
    with "<" <> rest <- id,
         true <- String.ends_with?(rest, ">"),
         inner = binary_part(rest, 0, byte_size(rest) - 1),
         true <- Enum.all?(:binary.bin_to_list(inner), &(&1 in 0x21..0x7E and &1 not in ~c"<>")),
         [left, right] when left != "" and right != "" <- String.split(inner, "@") do
      true
    else
      _ -> false
    end
  end

  defp fold_or_invalid(name, tokens) do
    case Header.fold(name, tokens) do
      {:ok, field} -> {:ok, field}
      :error -> invalid(:invalid_header_value, name)
    end
  end

  # Bodies and attachments

  defp body(email) do
    with {:ok, text} <- body_text(email.text, :text),
         {:ok, html} <- body_text(email.html, :html),
         {:ok, attachments} <- attachments(email.attachments) do
      content =
        case {text, html} do
          {nil, nil} ->
            nil

          {text, nil} ->
            text_part("plain", text)

          {nil, html} ->
            text_part("html", html)

          {text, html} ->
            multipart("alternative", [text_part("plain", text), text_part("html", html)])
        end

      cond do
        content == nil ->
          invalid(:missing_body, :text)

        attachments == [] ->
          {headers, body} = content
          {:ok, headers, body}

        true ->
          {headers, body} = multipart("mixed", [content | attachments])
          {:ok, headers, body}
      end
    end
  end

  defp body_text(nil, _field) do
    {:ok, nil}
  end

  defp body_text(text, field) do
    if is_binary(text) and String.valid?(text),
      do: {:ok, String.replace(text, ~r/\r\n|\r|\n/, "\r\n")},
      else: invalid(:invalid_body, field)
  end

  # A part is {header lines, body}.
  defp text_part(subtype, text) do
    {["Content-Type: text/#{subtype}; charset=UTF-8", "Content-Transfer-Encoding: base64"],
     base64_lines(text)}
  end

  defp multipart(subtype, parts) do
    boundary = "=_" <> random_hex()

    body =
      Enum.map_join(parts, "\r\n", fn {headers, body} ->
        "--" <> boundary <> "\r\n" <> Enum.join(headers, "\r\n") <> "\r\n\r\n" <> body
      end) <> "\r\n--" <> boundary <> "--"

    {:ok, content_type} =
      Header.fold("Content-Type", ["multipart/#{subtype};", ~s(boundary="#{boundary}")])

    {[content_type], body}
  end

  defp attachments(list) when is_list(list) do
    list |> Enum.map(&attachment/1) |> collect(:attachments)
  end

  defp attachments(_list) do
    invalid(:invalid_attachment, :attachments)
  end

  defp attachment(%{filename: filename, content_type: content_type, data: data})
       when is_binary(filename) and is_binary(content_type) and is_binary(data) do
    with true <- header_text?(filename) and filename != "",
         true <- byte_size(filename) <= @max_filename_bytes,
         true <- content_type?(content_type),
         {:ok, type} <- Header.fold("Content-Type", [content_type]),
         {:ok, disposition} <- Header.fold("Content-Disposition", disposition_tokens(filename)) do
      {:ok, {[type, disposition, "Content-Transfer-Encoding: base64"], base64_lines(data)}}
    else
      _ -> invalid(:invalid_attachment, :attachments)
    end
  end

  defp attachment(_attachment) do
    invalid(:invalid_attachment, :attachments)
  end

  # type/subtype MIME tokens; multipart and message types need structure the
  # builder doesn't write.
  defp content_type?(content_type) do
    case String.split(content_type, "/") do
      [type, subtype] ->
        Regex.match?(@mime_token, type) and Regex.match?(@mime_token, subtype) and
          String.downcase(type) not in ["multipart", "message"]

      _ ->
        false
    end
  end

  # An ASCII filename= for older readers, plus RFC 2231 filename* when the
  # fallback had to change anything.
  defp disposition_tokens(filename) do
    fallback =
      for <<char::utf8 <- filename>>, into: "" do
        if char in 0x20..0x7E and char not in ~c"\"\\", do: <<char>>, else: "_"
      end

    plain = ~s(filename="#{fallback}")

    if fallback == filename,
      do: ["attachment;", plain],
      else: ["attachment;", plain <> ";" | extended_filename(filename)]
  end

  # RFC 2231 continuations of percent-encoded UTF-8, split only between
  # encoded octets, each small enough for its own line.
  defp extended_filename(filename) do
    units =
      for <<byte <- filename>> do
        if byte in ?A..?Z or byte in ?a..?z or byte in ?0..?9 or byte in ~c"!#$&+-.^_`|~",
          do: <<byte>>,
          else: "%" <> Base.encode16(<<byte>>)
      end

    units
    |> Enum.chunk_while(
      "",
      fn unit, chunk ->
        if byte_size(chunk) + byte_size(unit) > 48,
          do: {:cont, chunk, unit},
          else: {:cont, chunk <> unit}
      end,
      fn chunk -> {:cont, chunk, ""} end
    )
    |> Enum.with_index()
    |> then(fn chunks ->
      last = length(chunks) - 1

      Enum.map(chunks, fn {chunk, index} ->
        charset = if index == 0, do: "UTF-8''", else: ""
        separator = if index < last, do: ";", else: ""
        "filename*#{index}*=" <> charset <> chunk <> separator
      end)
    end)
  end

  # 57 bytes encode to one 76-character base64 line.
  defp base64_lines(data) do
    data |> chunks() |> Enum.map_join("\r\n", &Base.encode64/1)
  end

  defp chunks(<<chunk::binary-size(57), rest::binary>>) do
    [chunk | chunks(rest)]
  end

  defp chunks(<<>>) do
    []
  end

  defp chunks(rest) do
    [rest]
  end

  # RFC 5322 date-time in UTC.
  defp date(datetime) do
    Calendar.strftime(datetime, "%a, %d %b %Y %H:%M:%S +0000")
  end

  defp random_hex do
    16 |> :crypto.strong_rand_bytes() |> Base.encode16(case: :lower)
  end
end
