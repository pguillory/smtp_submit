defmodule SMTPSubmit.EmailTest do
  use ExUnit.Case, async: true

  import SMTPSubmit.Email

  alias SMTPSubmit.Email
  alias SMTPSubmit.InvalidEmail

  defp email(overrides) do
    struct!(
      %Email{from: "me@example.com", to: ["you@example.com"], subject: "Hi", text: "Hello"},
      overrides
    )
  end

  defp build!(overrides, opts \\ []) do
    assert {:ok, message} = build(email(overrides), opts)
    assert_wire(message)
    message
  end

  defp invalid(overrides) do
    assert {:error, %InvalidEmail{} = error} = build(email(overrides))
    {error.reason, error.field}
  end

  # Every line is 7-bit, CRLF-terminated and at most 998 bytes; header lines
  # are at most 76 characters, as RFC 2047 requires of lines with encoded words.
  defp assert_wire(message) do
    refute String.ends_with?(message, "\r\n")
    refute message =~ ~r/\r(?!\n)|(?<!\r)\n/
    assert Enum.all?(:binary.bin_to_list(message), &(&1 <= 0x7F))
    [head | _] = String.split(message, "\r\n\r\n", parts: 2)
    for line <- String.split(message, "\r\n"), do: assert(byte_size(line) <= 998)
    for line <- String.split(head, "\r\n"), do: assert(byte_size(line) <= 76, line)
  end

  # Unfolded top-level header fields, in order (RFC 5322 section 2.2.3).
  defp fields(message) do
    [head | _] = String.split(message, "\r\n\r\n", parts: 2)

    head
    |> String.replace(~r/\r\n(?=[ \t])/, "")
    |> String.split("\r\n")
    |> Enum.map(fn line ->
      [name, value] = String.split(line, ":", parts: 2)
      {name, String.trim_leading(value, " ")}
    end)
  end

  defp field(message, name) do
    message |> fields() |> List.keyfind(name, 0) |> then(&(&1 && elem(&1, 1)))
  end

  # A small independent RFC 2047 B decoder. Whitespace between adjacent
  # encoded words is not part of the text; each word must hold whole UTF-8
  # characters on its own.
  defp decode_words(value) do
    value
    |> String.replace(~r/\?=[ \t]+=\?/, "?==?")
    |> then(
      &Regex.replace(~r/=\?UTF-8\?B\?([A-Za-z0-9+\/=]*)\?=/, &1, fn _, encoded ->
        decoded = Base.decode64!(encoded)
        assert String.valid?(decoded), "an encoded word split a UTF-8 character"
        decoded
      end)
    )
  end

  # gen_smtp's MIME parser as an independent oracle for structure, part headers
  # and decoded bodies. Its charset conversion needs an optional dependency, so
  # it runs with `encoding: none` and leaves headers raw. It logs every line it
  # reads at debug level; that chatter is lowered for this process only.
  defp decode(message) do
    Logger.put_process_level(self(), :info)
    :mimemail.decode(message, [{:encoding, :none}])
  after
    Logger.delete_process_level(self())
  end

  describe "headers" do
    test "writes the fields in order, with no Bcc" do
      message = build!(cc: [{"Carol", "carol@example.com"}], bcc: ["hidden@example.com"])

      assert Enum.map(fields(message), &elem(&1, 0)) == [
               "From",
               "To",
               "Cc",
               "Subject",
               "Date",
               "Message-ID",
               "MIME-Version",
               "Content-Type",
               "Content-Transfer-Encoding"
             ]

      refute message =~ "hidden@example.com"
    end

    test "writes Bcc only when asked, for a draft" do
      message = build!([bcc: ["hidden@example.com"]], bcc_header: true)
      assert field(message, "Bcc") == "hidden@example.com"
    end

    test "leaves out empty To and Cc" do
      message = build!(to: [], bcc: ["hidden@example.com"])
      refute field(message, "To")
      refute field(message, "Cc")
    end

    test "dates in RFC 5322 form, in UTC" do
      assert field(build!([]), "Date") =~
               ~r/\A(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d\d (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d\d:\d\d:\d\d \+0000\z/
    end

    test "generates a fresh Message-ID in the sender's domain" do
      first = field(build!(from: "me@mail.example.com"), "Message-ID")
      second = field(build!(from: "me@mail.example.com"), "Message-ID")
      assert first =~ ~r/\A<[0-9a-f]{32}@mail\.example\.com>\z/
      assert first != second
      assert new_message_id("me@example.com") =~ ~r/\A<[0-9a-f]{32}@example\.com>\z/
    end

    test "uses a caller's Message-ID instead" do
      id = new_message_id("me@example.com")
      message = build!(headers: [{"message-id", id}])
      assert field(message, "Message-ID") == id
      assert Enum.count(fields(message), &(String.downcase(elem(&1, 0)) == "message-id")) == 1
    end

    test "a caller's Message-ID must be a valid msg-id" do
      for id <- [
            "a@example.com",
            "<a:b@example.com>",
            "<a\"b@example.com>",
            "<a\\b@example.com>",
            "<a..b@example.com>",
            "<.a@example.com>",
            "<a.@example.com>",
            "<a@example..com>",
            "<a@b@example.com>",
            "<caf\u00e9@example.com>"
          ] do
        assert invalid(headers: [{"Message-ID", id}]) == {:invalid_header_value, "Message-ID"}, id
      end

      for id <- ["<a.b@example.com>", "<x@[127.0.0.1]>", "<a!b@c>"] do
        assert field(build!(headers: [{"Message-ID", id}]), "Message-ID") == id
      end
    end

    test "writes In-Reply-To and References as is, folding only between ids" do
      [first | _] = ids = for n <- 1..12, do: "<message-#{n}.thread@mail.example.com>"
      message = build!(headers: [{"In-Reply-To", first}, {"References", Enum.join(ids, " ")}])
      assert field(message, "In-Reply-To") == first
      assert String.split(field(message, "References")) == ids
    end

    test "In-Reply-To and References accept the obsolete forms received mail carries" do
      id = ~s(<"quoted local"@example.com>)
      message = build!(headers: [{"In-Reply-To", ~s(<"quoted@example.com>)}])
      assert field(message, "In-Reply-To") == ~s(<"quoted@example.com>)

      assert invalid(headers: [{"References", id}]) == {:invalid_header_value, "References"}

      for value <- [
            "",
            "no-brackets@example.com",
            "<@example.com>",
            "<a@>",
            "<caf\u00e9@example.com>"
          ] do
        assert invalid(headers: [{"References", value}]) == {:invalid_header_value, "References"}
      end
    end

    test "a msg-id too long for a line is refused" do
      id = "<" <> String.duplicate("a", 1000) <> "@example.com>"
      assert invalid(headers: [{"References", id}]) == {:invalid_header_value, "References"}
    end

    test "refuses a second Message-ID, In-Reply-To or References" do
      for name <- ["Message-ID", "In-Reply-To", "References"] do
        headers = [{name, "<a@example.com>"}, {String.upcase(name), "<b@example.com>"}]
        assert invalid(headers: headers) == {:duplicate_header, String.upcase(name)}
      end
    end

    test "refuses fields the builder writes itself" do
      for name <-
            ~w(From to CC Bcc Subject Date MIME-Version Content-Type content-transfer-encoding) do
        assert invalid(headers: [{name, "x"}]) == {:reserved_header, name}
      end
    end

    test "refuses invalid field names" do
      for name <- ["", "X Space", "X:Colon", "X-Caf\u00e9", "X\r\nsecret-value"] do
        assert {:error, error} = build(email(headers: [{name, "x"}]))
        assert {error.reason, error.field} == {:invalid_header_name, :headers}
        refute Exception.message(error) =~ "secret-value"
        refute inspect(error) =~ "secret-value"
      end

      assert invalid(headers: [:not_a_pair]) == {:invalid_header_name, :headers}
      assert invalid(headers: [{"X-Note", nil}]) == {:invalid_header_value, :headers}
    end

    test "other fields are ASCII text, folded at spaces" do
      value = Enum.map_join(1..40, " ", &"word#{&1}")
      message = build!(headers: [{"X-Note", value}, {"Reply-To", "team@example.com"}])
      assert field(message, "X-Note") == value
      assert field(message, "Reply-To") == "team@example.com"

      for bad <- ["caf\u00e9", "a\r\nBcc: x@example.com", "a\nb", "a\0b"] do
        assert invalid(headers: [{"X-Note", bad}]) == {:invalid_header_value, "X-Note"}
      end

      assert invalid(headers: [{"X-Note", String.duplicate("a", 1000)}]) ==
               {:invalid_header_value, "X-Note"}
    end
  end

  describe "subject" do
    test "keeps a short ASCII subject as is" do
      assert field(build!(subject: "Quarterly  plan"), "Subject") == "Quarterly  plan"
    end

    test "folds a long ASCII subject at spaces without changing it" do
      subject = Enum.map_join(1..30, " ", &"word#{&1}")
      message = build!(subject: subject)
      assert message =~ "\r\n word"
      assert field(message, "Subject") == subject
    end

    test "encodes non-ASCII text in words that never split a character" do
      subject = String.duplicate("Grüße aus Köln 🌍 ", 8)
      value = field(build!(subject: subject), "Subject")
      assert value =~ ~r/\A=\?UTF-8\?B\?/
      assert decode_words(value) == subject
    end

    test "encodes ASCII text that looks like an encoded word" do
      subject = "see =?UTF-8?B?SGk=?= here"
      value = field(build!(subject: subject), "Subject")
      assert value != subject
      assert decode_words(value) == subject
    end

    test "refuses control characters and invalid UTF-8" do
      for subject <- ["a\r\nBcc: x@example.com", "tab\there", <<0xFF>>, nil] do
        assert invalid(subject: subject) == {:invalid_subject, :subject}
      end
    end
  end

  describe "addresses" do
    test "quotes an ASCII display name, escaping quotes and backslashes" do
      message = build!(from: {~s(Jo "JJ" \\ Smith), "jo@example.com"})
      assert field(message, "From") == ~s("Jo \\"JJ\\" \\\\ Smith" <jo@example.com>)
    end

    test "encodes a non-ASCII or long display name" do
      for name <- ["Zoë Ödegaard", String.duplicate("Long Name ", 10)] do
        value = field(build!(from: {name, "z@example.com"}), "From")
        assert decode_words(value) == name <> " <z@example.com>"
      end
    end

    test "folds a long recipient list between and within mailboxes" do
      to = for n <- 1..30, do: {"Person #{n}", "person#{n}@example.com"}
      message = build!(to: to)

      assert field(message, "To") ==
               Enum.map_join(to, ", ", fn {name, address} -> ~s("#{name}" <#{address}>) end)
    end

    test "accepts dot-atom local parts and LDH domains" do
      for address <- [
            "a@b",
            "first.last+tag@mail.example.com",
            "x!#$%&'*+-/=?^_`{|}~@a-b.example"
          ] do
        assert field(build!(to: [address]), "To") == address
        assert valid_address?(address)
      end
    end

    test "refuses addresses outside the supported subset" do
      long = String.duplicate("a", 250) <> "@example.com"

      for address <- [
            "",
            "plain",
            ".a@example.com",
            "a.@example.com",
            "a..b@example.com",
            ~s("quoted"@example.com),
            "a@[127.0.0.1]",
            "a@-example.com",
            "a@example-.com",
            "a@example..com",
            "a b@example.com",
            "a@b@example.com",
            "caf\u00e9@example.com",
            "a@example.com\r\nBcc: x@example.com",
            long,
            nil
          ] do
        assert invalid(to: [address]) == {:invalid_address, :to}, inspect(address)
        refute valid_address?(address)
      end

      assert invalid(to: "you@example.com") == {:invalid_address, :to}
      assert invalid(from: {"Name", "bad"}) == {:invalid_address, :from}
    end

    test "refuses a display name with control characters" do
      assert invalid(cc: [{"Bad\r\nName", "c@example.com"}]) == {:invalid_display_name, :cc}
    end
  end

  describe "bodies" do
    test "a text body is UTF-8 base64 in 76-column lines with CRLF line endings" do
      text = String.duplicate("línea\n", 40) <> "end\rx"
      message = build!(text: text)
      assert field(message, "Content-Type") == "text/plain; charset=UTF-8"
      assert field(message, "Content-Transfer-Encoding") == "base64"
      [_head, body] = String.split(message, "\r\n\r\n", parts: 2)
      lines = String.split(body, "\r\n")
      assert Enum.all?(lines, &(byte_size(&1) <= 76))

      assert {"text", "plain", _, _, decoded} = decode(message)
      assert decoded == String.replace(text, ~r/\r\n|\r|\n/, "\r\n")
    end

    test "an HTML-only body is text/html" do
      assert {"text", "html", _, _, "<p>Hé</p>"} = decode(build!(text: nil, html: "<p>Hé</p>"))
    end

    test "text and HTML make multipart/alternative, plain first" do
      message = build!(text: "Hi", html: "<b>Hi</b>")

      assert {"multipart", "alternative", _, _,
              [{"text", "plain", _, _, "Hi"}, {"text", "html", _, _, "<b>Hi</b>"}]} =
               decode(message)
    end

    test "attachments make multipart/mixed after the body" do
      data = :crypto.strong_rand_bytes(300)

      message =
        build!(
          text: "Hi",
          html: "<b>Hi</b>",
          attachments: [
            %{filename: "report.pdf", content_type: "application/pdf", data: data},
            %{filename: "notes.txt", content_type: "text/plain", data: "a\nb"}
          ]
        )

      assert {"multipart", "mixed", _, _,
              [
                {"multipart", "alternative", _, _, [_, _]},
                {"application", "pdf", _, pdf, ^data},
                {"text", "plain", _, _, "a\nb"}
              ]} = decode(message)

      assert pdf.disposition == "attachment"
      assert pdf.disposition_params == [{"filename", "report.pdf"}]
    end

    test "a non-ASCII filename gets an ASCII fallback and RFC 2231 continuations" do
      filename = String.duplicate("Präsentation ", 6) <> "\"final\".pdf"
      attachment = %{filename: filename, content_type: "application/pdf", data: "x"}
      message = build!(attachments: [attachment])

      assert {"multipart", "mixed", _, _, [_body, {_, _, _, part, "x"}]} = decode(message)
      [{"filename", fallback} | extended] = part.disposition_params
      assert fallback =~ ~r/\A[ -~]+\z/
      refute fallback =~ ~s(")
      assert length(extended) > 1

      # Reassemble filename*0*, filename*1*, ... in order, and percent-decode.
      encoded =
        extended
        |> Enum.with_index()
        |> Enum.map_join(fn {{name, value}, index} ->
          assert name == "filename*#{index}*"
          value
        end)

      assert "UTF-8''" <> percent = encoded
      assert URI.decode(percent) == filename
    end

    test "refuses a missing or invalid body" do
      assert invalid(text: nil, html: nil) == {:missing_body, :text}
      assert invalid(text: <<0xFF>>) == {:invalid_body, :text}
      assert invalid(text: nil, html: <<0xFF>>) == {:invalid_body, :html}
    end

    test "refuses bad attachments" do
      for attachment <- [
            %{filename: "", content_type: "text/plain", data: ""},
            %{filename: "a\nb", content_type: "text/plain", data: ""},
            %{filename: <<0xFF>>, content_type: "text/plain", data: ""},
            %{filename: String.duplicate("a", 256), content_type: "text/plain", data: ""},
            %{filename: "a", content_type: "text", data: ""},
            %{filename: "a", content_type: "text/plain; charset=UTF-8", data: ""},
            %{filename: "a", content_type: "multipart/mixed", data: ""},
            %{filename: "a", content_type: "message/rfc822", data: ""},
            %{filename: "a", content_type: "text/plain", data: nil},
            {"a", "text/plain", ""}
          ] do
        assert invalid(attachments: [attachment]) == {:invalid_attachment, :attachments}
      end
    end
  end

  test "an empty body ends with the blank line after the headers" do
    assert {:ok, message} = build(email(text: ""))
    assert String.ends_with?(message, "Content-Transfer-Encoding: base64\r\n\r\n")
  end

  test "an invalid email's message and inspect never show the rejected value" do
    assert {:error, error} = build(email(to: ["secret-value"]))
    refute Exception.message(error) =~ "secret-value"
    refute inspect(error) =~ "secret-value"
  end
end
