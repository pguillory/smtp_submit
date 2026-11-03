defmodule SMTPSubmit.FakeServer.Peer do
  # Internal to SMTPSubmit.FakeServer: one client connection.
  @moduledoc false

  @login_username_prompt "334 VXNlcm5hbWU6"
  @login_password_prompt "334 UGFzc3dvcmQ6"
  @tls_handshake_timeout_ms 5_000

  def wait(server, config) do
    receive do
      {:socket, socket} -> start(server, config, socket)
    end
  end

  defp start(server, config, socket) do
    :ok = :inet.setopts(socket, packet: :line)

    state = %{
      server: server,
      config: config,
      transport: {:gen_tcp, socket},
      tls?: false,
      greeted?: false,
      authenticated?: false,
      from: nil,
      recipients: []
    }

    with {:ok, state} <- maybe_upgrade(state),
         {:ok, state} <- greet(state) do
      loop(state)
    end
  after
    GenServer.cast(server, :closed)
  end

  defp maybe_upgrade(%{config: %{tls: :implicit}} = state) do
    upgrade(state)
  end

  defp maybe_upgrade(state) do
    {:ok, state}
  end

  defp greet(state) do
    case command(state, :greeting) do
      nil -> ok(state, "220 localhost ESMTP SMTPSubmit fake")
      action -> act(state, action)
    end
  end

  defp upgrade(%{transport: {:gen_tcp, socket}} = state) do
    options = [
      certfile: String.to_charlist(state.config.certfile),
      keyfile: String.to_charlist(state.config.keyfile),
      cacertfile: String.to_charlist(state.config.chainfile),
      versions: [:"tlsv1.3", :"tlsv1.2"],
      mode: :binary,
      packet: :line,
      active: false,
      # Handshake failures are expected in tests; OTP's alerts are noise.
      log_level: :none
    ]

    case :ssl.handshake(socket, options, @tls_handshake_timeout_ms) do
      {:ok, socket} -> {:ok, %{state | transport: {:ssl, socket}, tls?: true, greeted?: false}}
      {:error, _reason} -> :tls_failed
    end
  end

  defp loop(state) do
    case read_line(state) do
      {:ok, line} ->
        case handle(state, line) do
          {:ok, state} -> loop(state)
          :stop -> :ok
        end

      :closed ->
        :ok
    end
  end

  defp handle(state, line) do
    {verb, argument} =
      case String.split(line, " ", parts: 2) do
        [verb, argument] -> {String.upcase(verb), argument}
        [verb] -> {String.upcase(verb), ""}
      end

    case verb do
      verb when verb in ["EHLO", "HELO"] -> ehlo(state, verb)
      "STARTTLS" -> starttls(state)
      "AUTH" -> auth(state, argument)
      "MAIL" -> mail(state, argument)
      "RCPT" -> rcpt(state, argument)
      "DATA" -> data(state)
      "RSET" -> ok(%{state | from: nil, recipients: []}, "250 2.0.0 OK")
      "NOOP" -> ok(state, "250 2.0.0 OK")
      "QUIT" -> quit(state)
      _ -> ok(state, "502 5.5.2 Unrecognized command")
    end
  end

  defp ehlo(state, verb) do
    with :default <- scripted(state, :ehlo) do
      state = %{state | greeted?: true, from: nil, recipients: []}

      if verb == "HELO" do
        ok(state, "250 localhost")
      else
        starttls = if state.config.tls == :starttls and not state.tls?, do: ["STARTTLS"], else: []

        auth =
          if auth_offered?(state),
            do: ["AUTH " <> Enum.join(state.config.auth_mechanisms, " ")],
            else: []

        lines = ["localhost"] ++ starttls ++ auth ++ ["8BITMIME"]
        ok(state, multiline(250, lines))
      end
    end
  end

  defp auth_offered?(state) do
    state.tls? or state.config.tls == :none
  end

  defp starttls(state) do
    cond do
      state.config.tls != :starttls or state.tls? ->
        ok(state, "502 5.5.1 STARTTLS not available")

      not state.greeted? ->
        ok(state, "503 5.5.1 EHLO first")

      true ->
        with :default <- scripted(state, :starttls) do
          reply(state, "220 2.0.0 Ready to start TLS")

          case upgrade(state) do
            {:ok, state} -> {:ok, state}
            :tls_failed -> :stop
          end
        end
    end
  end

  defp auth(state, argument) do
    {mechanism, initial} =
      case String.split(argument, " ", parts: 2) do
        [mechanism, initial] -> {String.upcase(mechanism), initial}
        [mechanism] -> {String.upcase(mechanism), nil}
      end

    cond do
      not auth_offered?(state) ->
        ok(state, "530 5.7.0 Must issue a STARTTLS command first")

      not state.greeted? or state.authenticated? ->
        ok(state, "503 5.5.1 Bad sequence of commands")

      mechanism not in state.config.auth_mechanisms ->
        ok(state, "504 5.7.4 Unrecognized authentication type")

      true ->
        case credentials(state, mechanism, initial) do
          {:ok, username, password} ->
            authenticated? =
              username == state.config.username and password == state.config.password

            # Recorded only after the exchange, so a scripted refusal follows it.
            case command(state, {:auth, mechanism}) do
              nil when authenticated? ->
                ok(%{state | authenticated?: true}, "235 2.7.0 Accepted")

              nil ->
                ok(state, "535 5.7.8 Username and Password not accepted")

              {:reply, text} = action ->
                with {:ok, state} <- act(state, action),
                     do: {:ok, %{state | authenticated?: String.starts_with?(text, "235")}}

              action ->
                act(state, action)
            end

          {:error, text} ->
            ok(state, text)

          :closed ->
            :stop
        end
    end
  end

  defp credentials(state, "LOGIN", nil) do
    reply(state, @login_username_prompt)

    with {:ok, username} <- read_base64(state) do
      reply(state, @login_password_prompt)

      with {:ok, password} <- read_base64(state), do: {:ok, username, password}
    end
  end

  defp credentials(state, "PLAIN", nil) do
    reply(state, "334 ")

    with {:ok, line} <- read_line(state), do: plain(line)
  end

  defp credentials(_state, "PLAIN", initial) do
    plain(initial)
  end

  defp credentials(_state, _mechanism, _initial) do
    {:error, "501 5.5.4 Syntax error"}
  end

  defp plain(encoded) do
    case Base.decode64(encoded) do
      {:ok, decoded} ->
        case :binary.split(decoded, <<0>>, [:global]) do
          [_authzid, username, password] -> {:ok, username, password}
          _ -> {:error, "501 5.5.2 Cannot decode response"}
        end

      :error ->
        {:error, "501 5.5.2 Cannot decode response"}
    end
  end

  defp read_base64(state) do
    with {:ok, line} <- read_line(state) do
      case Base.decode64(line) do
        {:ok, value} -> {:ok, value}
        :error -> {:error, "501 5.5.2 Cannot decode response"}
      end
    end
  end

  defp mail(state, argument) do
    with {:ok, address} <- path(argument, "FROM:") do
      cond do
        not state.authenticated? ->
          ok(state, "530 5.7.0 Authentication required")

        state.from ->
          ok(state, "503 5.5.1 Sender already specified")

        true ->
          with :default <- scripted(state, {:mail, address}),
               do: ok(%{state | from: address}, "250 2.1.0 OK")
      end
    else
      :error -> ok(state, "501 5.5.4 Syntax error in MAIL command")
    end
  end

  defp rcpt(state, argument) do
    with {:ok, address} <- path(argument, "TO:") do
      if state.from do
        with :default <- scripted(state, {:rcpt, address}),
             do: ok(%{state | recipients: state.recipients ++ [address]}, "250 2.1.5 OK")
      else
        ok(state, "503 5.5.1 Need MAIL before RCPT")
      end
    else
      :error -> ok(state, "501 5.5.4 Syntax error in RCPT command")
    end
  end

  # "FROM:<address>" or "TO:<address>", optionally followed by ESMTP parameters.
  defp path(argument, prefix) do
    size = byte_size(prefix)

    with <<given::binary-size(size), rest::binary>> <- argument,
         true <- String.upcase(given) == prefix,
         [_, address] <- Regex.run(~r/\A<([^<>\s]*)>(?: .*)?\z/, rest) do
      {:ok, address}
    else
      _ -> :error
    end
  end

  defp data(state) do
    if state.recipients == [] do
      ok(state, "503 5.5.1 Need RCPT before DATA")
    else
      with :default <- scripted(state, :data) do
        reply(state, "354 Go ahead")

        case read_data(state, []) do
          {:ok, data} -> data_end(state, data)
          :closed -> :stop
        end
      end
    end
  end

  defp read_data(state, lines) do
    case read_raw_line(state) do
      {:ok, ".\r\n"} ->
        data = lines |> Enum.reverse() |> IO.iodata_to_binary()
        # The CRLF before the terminating dot belongs to the terminator.
        {:ok, binary_part(data, 0, max(byte_size(data) - 2, 0))}

      {:ok, "." <> line} ->
        read_data(state, [line | lines])

      {:ok, line} ->
        read_data(state, [line | lines])

      :closed ->
        :closed
    end
  end

  defp data_end(state, data) do
    message = %{from: state.from, recipients: state.recipients, data: data}
    state = %{state | from: nil, recipients: []}

    case command(state, :data_end) do
      nil ->
        :ok = GenServer.call(state.server, {:accepted, message})
        ok(state, "250 2.0.0 OK queued as fake")

      {:reply, "2" <> _} = action ->
        :ok = GenServer.call(state.server, {:accepted, message})
        act(state, action)

      action ->
        act(state, action)
    end
  end

  defp quit(state) do
    with :default <- scripted(state, :quit) do
      reply(state, "221 2.0.0 Bye")
      :stop
    end
  end

  # Records the command and applies a scripted action, or returns :default.
  defp scripted(state, record) do
    case command(state, record) do
      nil -> :default
      action -> act(state, action)
    end
  end

  defp command(state, record) do
    GenServer.call(state.server, {:command, record})
  end

  defp act(state, {:reply, text}) do
    ok(state, text)
  end

  defp act(_state, :close) do
    :stop
  end

  # Stops answering: reads and ignores input until the client goes away.
  defp act(state, :stall) do
    case read_raw_line(state) do
      {:ok, _line} -> act(state, :stall)
      :closed -> :stop
    end
  end

  defp ok(state, text) do
    reply(state, text)
    {:ok, state}
  end

  defp multiline(code, lines) do
    {init, [last]} = Enum.split(lines, -1)

    Enum.map_join(init, "\r\n", &"#{code}-#{&1}") <>
      if(init == [], do: "", else: "\r\n") <> "#{code} #{last}"
  end

  defp reply(%{transport: {module, socket}}, text) do
    module.send(socket, text <> "\r\n")
  end

  defp read_line(state) do
    with {:ok, line} <- read_raw_line(state) do
      {:ok, String.trim_trailing(line, "\r\n")}
    end
  end

  defp read_raw_line(%{transport: {module, socket}}) do
    case module.recv(socket, 0) do
      {:ok, line} -> {:ok, line}
      {:error, _reason} -> :closed
    end
  end
end
