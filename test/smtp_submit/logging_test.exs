defmodule SMTPSubmit.LoggingTest do
  # Not async: it captures logs and raises the global log level, so OTP's TLS
  # notices and gen_smtp's own error reports would show if anything emitted them.
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog
  import SMTPSubmit

  require Logger

  alias SMTPSubmit.Email
  alias SMTPSubmit.Error
  alias SMTPSubmit.FakeServer

  setup do
    level = Logger.level()
    Logger.configure(level: :debug)
    on_exit(fn -> Logger.configure(level: level) end)
  end

  defp email do
    %Email{from: "me@example.com", to: ["a@example.com"], subject: "Hi", text: "Hello"}
  end

  defp config(endpoint, overrides) do
    Map.merge(
      %{
        host: endpoint.host,
        port: endpoint.port,
        cacertfile: endpoint.cacertfile,
        username: "fake-user",
        password: "fake-password"
      },
      overrides
    )
  end

  # Logs a notice-level sentinel first, so a passing refute shows capture was live.
  defp capture(fun) do
    log =
      capture_log([level: :debug], fn ->
        Logger.notice("capture sentinel")
        fun.()
      end)

    assert log =~ "capture sentinel"
    log
  end

  for tls <- [:starttls, :implicit] do
    @tls tls
    test "a certificate for another host logs nothing (#{tls})" do
      server =
        start_supervised!(
          {FakeServer,
           tls: @tls,
           certfile: "test/fixtures/wrong_host_tls/wrong-host.pem",
           keyfile: "test/fixtures/wrong_host_tls/wrong-host-key.pem"}
        )

      endpoint = FakeServer.endpoint(server)

      log =
        capture(fn ->
          assert {:error, %Error{code: :tls_failed}} =
                   deliver(
                     config(endpoint, %{tls: @tls, password: "canary-password-123"}),
                     email()
                   )
        end)

      # gen_smtp reports a failed STARTTLS upgrade through error_logger.
      refute log =~ "ssl upgrade"
      refute log =~ "wrong.example.test"
      refute log =~ endpoint.cacertfile
      refute log =~ "canary"
    end
  end

  test "a refused password logs nothing" do
    server = start_supervised!(FakeServer)
    endpoint = FakeServer.endpoint(server)

    log =
      capture(fn ->
        assert {:error, %Error{code: :auth_failed}} =
                 deliver(config(endpoint, %{password: "canary-password-123"}), email())
      end)

    refute log =~ "canary"
  end
end
