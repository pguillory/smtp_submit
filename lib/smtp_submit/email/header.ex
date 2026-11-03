defmodule SMTPSubmit.Email.Header do
  # Internal to SMTPSubmit.Email: header field encoding and folding.
  @moduledoc false

  # RFC 2047 caps a line holding an encoded word at 76 characters; every
  # folded line here keeps to that, below RFC 5322's 78-character advice.
  @soft_limit 76
  # RFC 5322: a physical line is at most 998 characters before its CRLF.
  @hard_limit 998
  # 45 bytes encode to 60 base64 characters: "=?UTF-8?B?" + 60 + "?=" is 72,
  # inside RFC 2047's 75-character word limit.
  @encoded_word_max_bytes 45

  @doc """
  Writes `name: tokens`, joining tokens with single spaces and folding before
  a token that would take its line past the soft limit. Returns `{:ok, field}`
  or `:error` when a token can't fit in a physical line.
  """
  def fold(name, tokens) do
    lines =
      Enum.reduce(tokens, [name <> ":"], fn token, [line | done] ->
        joined = line <> " " <> token

        if byte_size(joined) <= @soft_limit or token == "",
          do: [joined | done],
          else: [" " <> token, line | done]
      end)

    if Enum.all?(lines, &(byte_size(&1) <= @hard_limit)),
      do: {:ok, lines |> Enum.reverse() |> Enum.join("\r\n")},
      else: :error
  end

  @doc """
  Splits unstructured ASCII text into tokens that `fold/2` rejoins exactly:
  splits happen only at a single space before a non-space.
  """
  def words(text) do
    String.split(text, ~r/ (?=[^ ])/)
  end

  @doc "Whether every byte is printable ASCII or a space."
  def printable_ascii?(text) do
    Enum.all?(:binary.bin_to_list(text), &(&1 in 0x20..0x7E))
  end

  @doc """
  Encodes text as RFC 2047 B encoded words, never splitting a UTF-8
  character between two words.
  """
  def encoded_words(text) do
    text
    |> String.codepoints()
    |> Enum.reduce({[], ""}, fn char, {chunks, chunk} ->
      if chunk != "" and byte_size(chunk) + byte_size(char) > @encoded_word_max_bytes,
        do: {[chunk | chunks], char},
        else: {chunks, chunk <> char}
    end)
    |> then(fn {chunks, chunk} -> Enum.reverse([chunk | chunks]) end)
    |> Enum.map(&("=?UTF-8?B?" <> Base.encode64(&1) <> "?="))
  end

  @doc "A quoted-string with backslash escapes for `\"` and `\\`."
  def quoted(text) do
    "\"" <> String.replace(text, ~r/["\\]/, "\\\\\\0") <> "\""
  end
end
