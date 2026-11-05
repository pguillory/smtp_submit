defmodule SMTPSubmitTest do
  use ExUnit.Case, async: true

  import SMTPSubmit

  alias SMTPSubmit.Email
  alias SMTPSubmit.Error
  alias SMTPSubmit.FakeServer
  alias SMTPSubmit.InvalidEmail

  defp start_fake(opts \\ []) do
    server = start_supervised!({FakeServer, Keyword.put_new(opts, :observer, self())})
    {server, FakeServer.endpoint(server)}
  end

  defp config(overrides \\ []) do
    Map.merge(
      %{host: "smtp.example.test", port: 587, username: "fake-user", password: "fake-password"},
      Map.new(overrides)
    )
  end

  defp email(overrides \\ []) do
    struct!(
      %Email{
        from: {"Me", "me@example.com"},
        to: [{"Alice", "alice@example.com"}],
        cc: ["carol@example.com"],
        bcc: ["hidden@example.com"],
        subject: "Hello",
        text: "Hi there"
      },
      overrides
    )
  end

  # Points the config at the fake: its loopback host, port and CA.
  defp at(config, endpoint) do
    Map.merge(config, %{host: endpoint.host, port: endpoint.port, cacertfile: endpoint.cacertfile})
  end

  defp send_email(endpoint, opts \\ []) do
    {config, opts} = Keyword.pop(opts, :config, config())
    {email, opts} = Keyword.pop(opts, :email, email())
    deliver(config |> at(endpoint) |> Map.merge(Map.new(opts)), email)
  end

  defp auth_attempts(server) do
    server |> FakeServer.commands() |> Enum.filter(&match?({:auth, _}, &1))
  end

  describe "deliver/2" do
    test "sends the built message over STARTTLS to every recipient, without Bcc in it" do
      {server, endpoint} = start_fake()

      assert send_email(endpoint) == :ok

      assert [%{from: "me@example.com", recipients: recipients, data: data}] =
               FakeServer.messages(server)

      assert recipients == ["alice@example.com", "carol@example.com", "hidden@example.com"]
      assert data =~ "\r\nSubject: Hello\r\n"
      refute data =~ "hidden@example.com"
      refute data =~ ~r/^Bcc:/mi
    end

    test "upgrades to TLS and repeats EHLO before authenticating" do
      {server, endpoint} = start_fake()
      :ok = send_email(endpoint)
      assert_receive {:smtp_fake, ^server, :quit}

      assert FakeServer.commands(server) == [
               :greeting,
               :ehlo,
               :starttls,
               :ehlo,
               {:auth, "LOGIN"},
               {:mail, "me@example.com"},
               {:rcpt, "alice@example.com"},
               {:rcpt, "carol@example.com"},
               {:rcpt, "hidden@example.com"},
               :data,
               :data_end,
               :quit
             ]
    end

    test "uses implicit TLS without STARTTLS" do
      {server, endpoint} = start_fake(tls: :implicit)
      assert :ok = send_email(endpoint, tls: :implicit)
      refute :starttls in FakeServer.commands(server)
      assert [_] = FakeServer.messages(server)
    end

    test "sends to an exact duplicate recipient once" do
      {server, endpoint} = start_fake()
      email = email(to: ["a@example.com"], cc: ["a@example.com"], bcc: ["b@example.com"])
      :ok = send_email(endpoint, email: email)
      assert [%{recipients: ["a@example.com", "b@example.com"]}] = FakeServer.messages(server)
    end

    test "a Bcc-only email has no To or Cc header" do
      {server, endpoint} = start_fake()
      :ok = send_email(endpoint, email: email(to: [], cc: []))
      assert [%{recipients: ["hidden@example.com"], data: data}] = FakeServer.messages(server)
      refute data =~ ~r/^(To|Cc|Bcc):/mi
    end

    test "an invalid email fails before connecting" do
      {server, endpoint} = start_fake()

      assert {:error, %InvalidEmail{reason: :invalid_address, field: :to}} =
               send_email(endpoint, email: email(to: ["not an address"]))

      assert {:error, %InvalidEmail{reason: :invalid_address, field: :bcc}} =
               send_email(endpoint, email: email(bcc: ["bad address"]))

      assert FakeServer.commands(server) == []
    end

    test "an email without recipients fails before connecting" do
      {server, endpoint} = start_fake()

      assert {:error, %InvalidEmail{reason: :no_recipients}} =
               send_email(endpoint, email: email(to: [], cc: [], bcc: []))

      assert FakeServer.commands(server) == []
    end
  end

  describe "send/4" do
    test "sends finished text unchanged, dot-stuffing lines that start with a dot" do
      {server, endpoint} = start_fake()
      message = "Subject: dots\r\n\r\n.one\r\n..two\r\n.\r\nend"

      assert send(at(config(), endpoint), "me@example.com", ["a@example.com"], message) == :ok

      assert FakeServer.messages(server) == [
               %{from: "me@example.com", recipients: ["a@example.com"], data: message}
             ]
    end

    test "accepts a line of exactly 998 bytes" do
      {server, endpoint} = start_fake()
      message = "Subject: x\r\n\r\n" <> String.duplicate("a", 998)
      :ok = send(at(config(), endpoint), "me@example.com", ["a@example.com"], message)
      assert [%{data: ^message}] = FakeServer.messages(server)
    end

    test "drops one trailing CRLF, which the DATA terminator supplies" do
      {server, endpoint} = start_fake()

      :ok =
        send(
          at(config(), endpoint),
          "me@example.com",
          ["a@example.com"],
          "Subject: x\r\n\r\nbody\r\n"
        )

      assert [%{data: "Subject: x\r\n\r\nbody"}] = FakeServer.messages(server)
    end

    test "refuses message text that is not 7-bit CRLF lines of at most 998 bytes" do
      {server, endpoint} = start_fake()
      config = at(config(), endpoint)

      for message <- [
            "",
            "Subject: x\n\nbare LF",
            "Subject: x\r\n\r\nbare\rCR",
            "Subject: x\r\n\r\n\r\n.\nsmuggled",
            "Subject: x\r\n\r\nnul\0byte",
            "Subject: caf\u00e9\r\n\r\nbody",
            "Subject: x\r\n\r\n" <> String.duplicate("a", 999)
          ] do
        assert {:error, %InvalidEmail{reason: :invalid_message, field: :message}} =
                 send(config, "me@example.com", ["a@example.com"], message)
      end

      assert FakeServer.commands(server) == []
    end

    test "refuses a bad envelope before connecting" do
      {server, endpoint} = start_fake()
      config = at(config(), endpoint)
      message = "Subject: x\r\n\r\nbody"

      assert {:error, %InvalidEmail{reason: :invalid_address, field: :from}} =
               send(config, "me", ["a@example.com"], message)

      assert {:error, %InvalidEmail{reason: :no_recipients}} =
               send(config, "me@example.com", [], message)

      assert {:error, %InvalidEmail{reason: :invalid_address, field: :recipients}} =
               send(config, "me@example.com", ["a@example.com", "b..c@example.com"], message)

      assert FakeServer.commands(server) == []
    end

    test "an EHLO name that isn't a plain domain raises without showing the password" do
      config = %{config() | password: "canary-password-123"} |> Map.put(:hostname, "a\r\nRSET")

      error = assert_raise ArgumentError, fn -> send(config, "a@b", ["c@d"], "x") end
      refute Exception.message(error) =~ "canary"
    end

    test "deliver/2 with something other than an Email raises without showing the password" do
      config = %{config() | password: "canary-password-123"}
      error = assert_raise ArgumentError, fn -> deliver(config, %{to: ["c@d"]}) end
      refute Exception.message(error) =~ "canary"
    end

    test "a config without the required keys raises without showing the password" do
      error =
        assert_raise ArgumentError, fn ->
          send(%{host: "smtp.example.test", password: "canary-password-123"}, "a@b", ["c@d"], "x")
        end

      refute Exception.message(error) =~ "canary"
    end
  end

  describe "TLS policy" do
    # The fake's leaf is signed by an intermediate, as every real provider's is.
    test "verifies a chain with an intermediate CA over STARTTLS and implicit TLS" do
      {_server, endpoint} = start_fake()
      assert :ok = send_email(endpoint)
      stop_supervised!(FakeServer)

      {_server, endpoint} = start_fake(tls: :implicit)
      assert :ok = send_email(endpoint, tls: :implicit)
    end

    # gen_smtp's own implicit-TLS options carry {depth, 0}; this shows the
    # fixture chain really needs the depth SMTPSubmit passes.
    test "the fixture chain fails verification at gen_smtp's default depth" do
      {_server, endpoint} = start_fake()

      tls = [
        verify: :verify_peer,
        versions: [:"tlsv1.3", :"tlsv1.2"],
        depth: 0,
        cacertfile: String.to_charlist(endpoint.cacertfile),
        server_name_indication: ~c"localhost",
        customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)],
        log_level: :none
      ]

      assert {:error, _, {:temporary_failure, _, :tls_failed}} =
               :gen_smtp_client.open(
                 relay: ~c"localhost",
                 port: endpoint.port,
                 username: "fake-user",
                 password: "fake-password",
                 auth: :always,
                 tls: :always,
                 tls_options: tls,
                 retries: 0,
                 no_mx_lookups: true,
                 hostname: "client.example.test",
                 timeout: 5_000
               )
    end

    test "refuses a certificate for another host before sending credentials" do
      for tls <- [:starttls, :implicit] do
        {server, endpoint} =
          start_fake(
            tls: tls,
            certfile: "test/fixtures/wrong_host_tls/wrong-host.pem",
            keyfile: "test/fixtures/wrong_host_tls/wrong-host-key.pem"
          )

        assert {:error, %Error{code: :tls_failed, stage: :open}} =
                 send_email(endpoint, tls: tls)

        assert auth_attempts(server) == []
        stop_supervised!(FakeServer)
      end
    end

    test "refuses a server signed by an untrusted CA" do
      for tls <- [:starttls, :implicit] do
        {server, endpoint} = start_fake(tls: tls)

        assert {:error, %Error{code: :tls_failed}} =
                 send_email(endpoint, tls: tls, cacertfile: nil)

        assert auth_attempts(server) == []
        stop_supervised!(FakeServer)
      end
    end

    test "checks an IP-literal host against the certificate's IP SAN" do
      for tls <- [:starttls, :implicit] do
        {server, endpoint} = start_fake(tls: tls)
        endpoint = %{endpoint | host: "127.0.0.1"}
        assert :ok = send_email(endpoint, tls: tls)
        assert [_] = FakeServer.messages(server)
        stop_supervised!(FakeServer)

        {server, endpoint} =
          start_fake(
            tls: tls,
            certfile: "test/fixtures/wrong_host_tls/wrong-host.pem",
            keyfile: "test/fixtures/wrong_host_tls/wrong-host-key.pem"
          )

        endpoint = %{endpoint | host: "127.0.0.1"}

        assert {:error, %Error{code: :tls_failed}} =
                 send_email(endpoint, tls: tls)

        assert auth_attempts(server) == []
        stop_supervised!(FakeServer)
      end
    end

    test "a refused STARTTLS is a refusal during open, before credentials are sent" do
      {server, endpoint} = start_fake()
      :ok = FakeServer.script(server, :starttls, {:reply, "454 4.7.0 TLS not available"})

      assert {:error,
              %Error{code: :rejected, stage: :open, reply_code: 454, outcome_unknown?: false}} =
               send_email(endpoint)

      assert auth_attempts(server) == []
    end

    test "refuses a server that does not offer STARTTLS before sending credentials" do
      {server, endpoint} = start_fake(tls: :none)

      assert {:error, %Error{code: :tls_unavailable, stage: :open}} = send_email(endpoint)
      assert auth_attempts(server) == []
    end

    test "the TLS mode follows :tls, never falling back" do
      {server, endpoint} = start_fake(tls: :starttls)

      assert {:error, %Error{stage: :open}} =
               send_email(endpoint, tls: :implicit, open_timeout: 2_000)

      assert auth_attempts(server) == []
      stop_supervised!(FakeServer)

      {server, endpoint} = start_fake(tls: :implicit)

      assert {:error, %Error{stage: :open}} =
               send_email(endpoint, tls: :starttls, open_timeout: 2_000)

      assert auth_attempts(server) == []
    end
  end

  describe "authentication" do
    test "a refused password is an auth failure with each mechanism's refusal code" do
      {server, endpoint} = start_fake()

      assert {:error, %Error{code: :auth_failed, stage: :open, reply_code: 535} = error} =
               send_email(endpoint, config: config(password: "wrong-password"))

      assert error.auth_reply_codes == [535, 535]
      refute error.outcome_unknown?
      assert auth_attempts(server) == [{:auth, "LOGIN"}, {:auth, "PLAIN"}]
      assert FakeServer.messages(server) == []
    end

    test "the codes follow the server's replies to each attempt" do
      for {reply, codes} <- [
            {"534 5.7.9 Application-specific password required", [534, 535]},
            {"454 4.7.0 Temporary authentication failure", [454, 535]}
          ] do
        {server, endpoint} = start_fake()
        :ok = FakeServer.script(server, :auth, {:reply, reply})

        assert {:error, %Error{code: :auth_failed, reply_code: 535, auth_reply_codes: ^codes}} =
                 send_email(endpoint, config: config(password: "wrong-password"))

        stop_supervised!(FakeServer)
      end

      # A mechanism the server offers but refuses outright, before LOGIN and PLAIN.
      {_server, endpoint} = start_fake(auth_mechanisms: ["CRAM-MD5", "LOGIN", "PLAIN"])

      assert {:error, %Error{code: :auth_failed, auth_reply_codes: [501, 535, 535]}} =
               send_email(endpoint, config: config(password: "wrong-password"))
    end

    test "every refusal gen_smtp traces adds its code; other replies and traces add none" do
      assert {:error, %Error{code: :auth_failed, reply_code: 535} = error} =
               deliver(
                 Map.put(config(), :client, SMTPSubmit.Test.TracedRefusalClient),
                 email()
               )

      assert error.auth_reply_codes == [504, 535, 454, 534, 535]
      refute inspect(error) =~ "fake-password"
    end

    test "other failures carry no AUTH codes" do
      {_server, endpoint} = start_fake(tls: :none)
      assert {:error, %Error{auth_reply_codes: []}} = send_email(endpoint)
    end

    test "falls back to AUTH PLAIN when AUTH LOGIN is refused" do
      {server, endpoint} = start_fake()
      :ok = FakeServer.script(server, :auth, {:reply, "535 5.7.8 not now"})

      assert :ok = send_email(endpoint)
      assert auth_attempts(server) == [{:auth, "LOGIN"}, {:auth, "PLAIN"}]
    end

    test "a 535 after sign-in is a delivery refusal, not an auth failure" do
      {server, endpoint} = start_fake()
      :ok = FakeServer.script(server, :mail, {:reply, "535 5.7.8 Authentication required"})

      assert {:error, %Error{code: :rejected, stage: :deliver, reply_code: 535} = error} =
               send_email(endpoint)

      refute error.outcome_unknown?
    end

    test "credentials appear in no command record or error" do
      {server, endpoint} = start_fake(password: "server-only-secret")

      assert {:error, error} =
               send_email(endpoint, config: config(password: "canary-password-123"))

      refute inspect(error) =~ "canary"
      refute Exception.message(error) =~ "canary"
      refute inspect(FakeServer.commands(server)) =~ "canary"
    end
  end

  describe "refusals" do
    test "a refused greeting fails once without retrying" do
      for reply <- ["554 5.7.1 go away", "421 4.3.2 busy"] do
        {server, endpoint} = start_fake()
        :ok = FakeServer.script(server, :greeting, {:reply, reply})
        code = String.to_integer(binary_part(reply, 0, 3))

        assert {:error, %Error{code: :rejected, stage: :open, reply_code: ^code}} =
                 send_email(endpoint)

        assert Enum.count(FakeServer.commands(server), &(&1 == :greeting)) == 1
        stop_supervised!(FakeServer)
      end
    end

    test "4xx and 5xx replies during delivery are definite refusals" do
      for {kind, reply} <- [
            rcpt: "550 5.1.1 No such user",
            data: "554 5.7.0 no",
            data_end: "552 5.3.4 Message too big",
            data_end: "451 4.3.0 try later"
          ] do
        {server, endpoint} = start_fake()
        :ok = FakeServer.script(server, kind, {:reply, reply})
        code = String.to_integer(binary_part(reply, 0, 3))

        assert {:error,
                %Error{
                  code: :rejected,
                  stage: :deliver,
                  reply_code: ^code,
                  outcome_unknown?: false
                }} = send_email(endpoint)

        assert FakeServer.messages(server) == []
        stop_supervised!(FakeServer)
      end
    end

    test "a malformed 4 or 5 reply is not a definite refusal" do
      for reply <- ["4ab try later", "5x0 no"] do
        {server, endpoint} = start_fake()
        :ok = FakeServer.script(server, :data_end, {:reply, reply})

        assert {:error,
                %Error{
                  code: :protocol,
                  stage: :deliver,
                  reply_code: nil,
                  outcome_unknown?: true
                }} = send_email(endpoint)

        stop_supervised!(FakeServer)
      end
    end
  end

  describe "unknown outcomes" do
    # Each of these follows the final dot, so the server may have taken the message.
    test "a bare 250 acceptance has an unknown outcome" do
      {server, endpoint} = start_fake()
      :ok = FakeServer.script(server, :data_end, {:reply, "250"})

      assert {:error, %Error{code: :protocol, stage: :deliver, outcome_unknown?: true}} =
               send_email(endpoint)

      assert [_] = FakeServer.messages(server)
    end

    test "a multiline 250 acceptance has an unknown outcome" do
      {server, endpoint} = start_fake()
      :ok = FakeServer.script(server, :data_end, {:reply, "250-queued\r\n250 as fake"})

      assert {:error,
              %Error{
                code: :protocol,
                stage: :deliver,
                reply_code: 250,
                outcome_unknown?: true
              }} = send_email(endpoint)

      assert [_] = FakeServer.messages(server)
    end

    test "an unparseable reply has an unknown outcome" do
      {server, endpoint} = start_fake()
      :ok = FakeServer.script(server, :data_end, {:reply, "2.0.0 ok"})

      assert {:error, %Error{code: :protocol, outcome_unknown?: true}} = send_email(endpoint)
    end

    test "a reply that makes the dependency raise has an unknown outcome" do
      {server, endpoint} = start_fake()
      :ok = FakeServer.script(server, :data_end, {:reply, ""})

      assert {:error, %Error{code: :protocol, stage: :deliver, outcome_unknown?: true}} =
               send_email(endpoint)
    end

    test "a dropped connection after the message has an unknown outcome" do
      {server, endpoint} = start_fake()
      :ok = FakeServer.script(server, :data_end, :close)

      assert {:error, %Error{code: :network, stage: :deliver, outcome_unknown?: true}} =
               send_email(endpoint)
    end

    test "a stalled acceptance times out with an unknown outcome and closes the connection" do
      {server, endpoint} = start_fake()
      :ok = FakeServer.script(server, :data_end, :stall)

      assert {:error,
              %Error{
                code: :timeout,
                stage: :deliver,
                timeout_ms: 1_500,
                outcome_unknown?: true
              }} = send_email(endpoint, deliver_timeout: 1_500)

      assert_receive {:smtp_fake, ^server, :data_end}
      assert_receive {:smtp_fake, ^server, :closed}
      assert FakeServer.messages(server) == []
    end
  end

  describe "deadlines and cleanup" do
    # The open deadline must leave a loaded scheduler time to connect; a
    # deadline that expires before the connection exists has nothing to close.
    test "a stalled greeting times out during open, which never sent the message" do
      {server, endpoint} = start_fake()
      :ok = FakeServer.script(server, :greeting, :stall)

      assert {:error,
              %Error{
                code: :timeout,
                stage: :open,
                timeout_ms: 2_000,
                outcome_unknown?: false
              }} =
               send_email(endpoint, open_timeout: 2_000)

      assert_receive {:smtp_fake, ^server, :greeting}
      assert_receive {:smtp_fake, ^server, :closed}
      assert FakeServer.messages(server) == []
    end

    test "a malformed reply that makes the dependency raise during open is a protocol error" do
      {server, endpoint} = start_fake()
      :ok = FakeServer.script(server, :greeting, {:reply, ""})

      assert {:error, %Error{code: :protocol, stage: :open, outcome_unknown?: false}} =
               send_email(endpoint)
    end

    test "an accepted send stays accepted when cleanup never finishes" do
      {server, endpoint} = start_fake()

      assert :ok =
               send_email(endpoint,
                 client: SMTPSubmit.Test.StallingCloseClient,
                 cleanup_timeout: 100
               )

      assert [_] = FakeServer.messages(server)
      # The killed worker's socket closes with it.
      assert_receive {:smtp_fake, ^server, :closed}
    end

    test "a dead caller cancels the send and closes the connection" do
      {server, endpoint} = start_fake()
      :ok = FakeServer.script(server, :mail, :stall)
      caller = spawn(fn -> send_email(endpoint) end)

      assert_receive {:smtp_fake, ^server, {:mail, _}}
      Process.exit(caller, :kill)
      assert_receive {:smtp_fake, ^server, :closed}
      assert FakeServer.messages(server) == []
    end

    test "leaves no reply in the caller's mailbox" do
      {_server, endpoint} = start_fake(observer: nil)
      :ok = send_email(endpoint)
      assert Process.info(self(), :messages) == {:messages, []}
    end
  end
end
