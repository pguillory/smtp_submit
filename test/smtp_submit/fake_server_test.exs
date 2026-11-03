defmodule SMTPSubmit.FakeServerTest do
  use ExUnit.Case, async: true

  alias SMTPSubmit.FakeServer

  defp connect(opts) do
    server = start_supervised!({FakeServer, [observer: self()] ++ opts})
    %{port: port} = FakeServer.endpoint(server)
    {:ok, socket} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, packet: :line, active: false])
    {server, socket}
  end

  defp exchange(socket, line) do
    :ok = :gen_tcp.send(socket, line <> "\r\n")
    read_reply(socket)
  end

  # Reads one possibly multiline reply.
  defp read_reply(socket, lines \\ []) do
    {:ok, line} = :gen_tcp.recv(socket, 0, 5_000)
    lines = [String.trim_trailing(line, "\r\n") | lines]

    case line do
      <<_code::binary-size(3), "-", _::binary>> -> read_reply(socket, lines)
      _ -> lines |> Enum.reverse() |> Enum.join("\n")
    end
  end

  defp plain(user, password) do
    Base.encode64(<<0>> <> user <> <<0>> <> password)
  end

  defp sign_in(socket) do
    "220 " <> _ = read_reply(socket)
    "250" <> _ = exchange(socket, "EHLO client")
    "235" <> _ = exchange(socket, "AUTH PLAIN " <> plain("fake-user", "fake-password"))
  end

  test "offers AUTH only after STARTTLS and refuses it before" do
    {_server, socket} = connect(tls: :starttls)
    assert "220 " <> _ = read_reply(socket)

    ehlo = exchange(socket, "EHLO client")
    assert ehlo =~ "STARTTLS"
    refute ehlo =~ "AUTH"

    assert "530 " <> _ =
             exchange(socket, "AUTH PLAIN " <> plain("fake-user", "fake-password"))

    assert "530 " <> _ = exchange(socket, "MAIL FROM:<me@example.com>")
  end

  test "enforces the command sequence" do
    {_server, socket} = connect(tls: :none)
    assert "220 " <> _ = read_reply(socket)
    assert "502 " <> _ = exchange(socket, "STARTTLS")
    assert "250" <> _ = exchange(socket, "EHLO client")
    assert "530 " <> _ = exchange(socket, "MAIL FROM:<me@example.com>")
    assert "535 " <> _ = exchange(socket, "AUTH PLAIN " <> plain("fake-user", "wrong"))
    assert "504 " <> _ = exchange(socket, "AUTH CRAM-MD5")
    assert "235 " <> _ = exchange(socket, "AUTH PLAIN " <> plain("fake-user", "fake-password"))
    assert "503 " <> _ = exchange(socket, "RCPT TO:<a@example.com>")
    assert "503 " <> _ = exchange(socket, "DATA")
    assert "250 " <> _ = exchange(socket, "MAIL FROM:<me@example.com>")
    assert "503 " <> _ = exchange(socket, "MAIL FROM:<me@example.com>")
    assert "503 " <> _ = exchange(socket, "DATA")
    assert "501 " <> _ = exchange(socket, "RCPT TO:no-brackets@example.com")
    assert "502 " <> _ = exchange(socket, "VRFY a")
    assert "221 " <> _ = exchange(socket, "QUIT")
  end

  test "unstuffs DATA and records the message without the terminator" do
    {server, socket} = connect(tls: :none)
    sign_in(socket)
    assert "250 " <> _ = exchange(socket, "MAIL FROM:<me@example.com>")
    assert "250 " <> _ = exchange(socket, "RCPT TO:<a@example.com>")
    assert "250 " <> _ = exchange(socket, "RCPT TO:<a@example.com>")
    assert "354 " <> _ = exchange(socket, "DATA")
    :ok = :gen_tcp.send(socket, "Subject: x\r\n\r\n..leading dot\r\nlast\r\n")
    assert "250 " <> _ = exchange(socket, ".")

    assert FakeServer.messages(server) == [
             %{
               from: "me@example.com",
               recipients: ["a@example.com", "a@example.com"],
               data: "Subject: x\r\n\r\n.leading dot\r\nlast"
             }
           ]
  end

  test "records commands without AUTH payloads and reports closed connections" do
    {server, socket} = connect(tls: :none)
    sign_in(socket)
    :ok = :gen_tcp.close(socket)

    assert_receive {:smtp_fake, ^server, :closed}
    assert FakeServer.commands(server) == [:greeting, :ehlo, {:auth, "PLAIN"}]
  end

  test "scripted replies replace the next command's answer once" do
    {server, socket} = connect(tls: :none)
    :ok = FakeServer.script(server, :ehlo, {:reply, "250-custom\r\n250 done"})
    assert "220 " <> _ = read_reply(socket)
    assert exchange(socket, "EHLO client") == "250-custom\n250 done"
    assert exchange(socket, "EHLO client") =~ "AUTH LOGIN PLAIN"
  end

  test "a scripted AUTH refusal rejects valid credentials" do
    {server, socket} = connect(tls: :none)
    :ok = FakeServer.script(server, :auth, {:reply, "535 5.7.8 no"})
    assert "220 " <> _ = read_reply(socket)
    assert "250" <> _ = exchange(socket, "EHLO client")
    assert "535 " <> _ = exchange(socket, "AUTH PLAIN " <> plain("fake-user", "fake-password"))
    assert "530 " <> _ = exchange(socket, "MAIL FROM:<me@example.com>")
  end

  test "rejects invalid scripts" do
    server = start_supervised!(FakeServer)
    assert FakeServer.script(server, :vrfy, :stall) == {:error, :invalid_script}
    assert FakeServer.script(server, :mail, :explode) == {:error, :invalid_script}
    assert FakeServer.script(server, :mail, {:reply, 550}) == {:error, :invalid_script}
  end

  test "a scripted close on the greeting drops the connection" do
    server = start_supervised!({FakeServer, tls: :none, observer: self()})
    :ok = FakeServer.script(server, :greeting, :close)
    %{port: port} = FakeServer.endpoint(server)
    {:ok, socket} = :gen_tcp.connect(~c"127.0.0.1", port, [:binary, active: false])

    assert {:error, :closed} = :gen_tcp.recv(socket, 0, 5_000)
    assert_receive {:smtp_fake, ^server, :closed}
  end

  test "redacts its password from process status" do
    server = start_supervised!({FakeServer, password: "status-canary"})
    status = inspect(:sys.get_status(server))
    refute status =~ "status-canary"
    assert status =~ "password: :redacted"
  end

  test "listens on loopback only" do
    server = start_supervised!(FakeServer)
    %{port: port, host: "localhost"} = FakeServer.endpoint(server)
    {:ok, addresses} = :inet.getifaddrs()

    external =
      for {_name, options} <- addresses,
          {:addr, {a, _, _, _} = address} <- options,
          a != 127,
          do: address

    for address <- external do
      assert {:error, _} = :gen_tcp.connect(address, port, [], 1_000)
    end
  end
end
