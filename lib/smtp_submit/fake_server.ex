defmodule SMTPSubmit.FakeServer do
  @moduledoc """
  Stateful, loopback-only SMTP submission server for exercising the real
  `SMTPSubmit` client and its `gen_smtp` dependency over real sockets.

  It parses and enforces the server side independently (it does not use
  `gen_smtp_server`): greeting, EHLO/HELO, STARTTLS with a fresh EHLO after
  the upgrade, AUTH LOGIN/PLAIN against its own seeded credentials, the
  MAIL/RCPT/DATA sequence, dot-unstuffing, RSET, NOOP and QUIT.

  Start an isolated instance with `start_supervised!({FakeServer, opts})`.
  Options:

  * `:name` - registered name; default nil
  * `:tls` - `:starttls` (default; AUTH is offered only after the upgrade),
    `:implicit` (TLS from the first byte, as on port 465) or `:none`
    (plaintext, never offers STARTTLS)
  * `:certfile`, `:keyfile`, `:chainfile` - the server identity; default the
    synthetic `localhost` leaf and intermediate in `priv/fake_tls`; trust
    them with `ca_file/0`
  * `:username`, `:password` - the only accepted credentials; default
    `fake-user` / `fake-password`
  * `:auth_mechanisms` - advertised mechanisms; default `["LOGIN", "PLAIN"]`
  * `:observer` - a pid sent `{:smtp_fake, server, event}` for each command
    record and `:closed` when a connection ends

  `endpoint/1` returns `%{host: "localhost", port:, cacertfile:}`, network and
  trust fields only; the client must still present matching credentials.
  `commands/1` lists command records in arrival order: atoms such as `:ehlo`,
  `:starttls`, `:data`, `:data_end` and `:quit`, plus `{:auth, mechanism}`,
  `{:mail, address}` and `{:rcpt, address}`. It never records AUTH payloads.
  `messages/1` lists accepted messages as `%{from:, recipients:, data:}` with
  the unstuffed DATA bytes.

  `script/3` queues one action for the next command of a kind (`:greeting`,
  `:ehlo`, `:starttls`, `:auth`, `:mail`, `:rcpt`, `:data`, `:data_end` or
  `:quit`): `{:reply, text}` answers with raw reply text instead (CRLF is
  added; separate lines with CRLF), `:stall` ignores everything until the
  client disconnects and `:close` drops the connection. An `:auth` reply
  authenticates only if it starts with
  235; a `:data_end` reply accepts the message only if it starts with 2.
  """

  use GenServer

  alias SMTPSubmit.FakeServer.Peer

  @kinds [:greeting, :ehlo, :starttls, :auth, :mail, :rcpt, :data, :data_end, :quit]

  @doc "Starts an isolated fake listener; returns `{:ok, pid}` or a listener/start error."
  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, Keyword.take(opts, [:name]))
  end

  @doc "Returns the loopback host, port and CA file a client should use."
  def endpoint(server) do
    GenServer.call(server, :endpoint)
  end

  @doc "Returns command records in arrival order, without AUTH payloads."
  def commands(server) do
    GenServer.call(server, :commands)
  end

  @doc "Returns accepted messages in arrival order."
  def messages(server) do
    GenServer.call(server, :messages)
  end

  @doc "Queues one action for the next command of `kind`; returns :ok or {:error, :invalid_script}."
  def script(server, kind, action) do
    GenServer.call(server, {:script, kind, action})
  end

  @doc """
  The synthetic root CA that signs the default identity. Point a client's
  `:cacertfile` at it to trust the fake; never install it anywhere.
  """
  def ca_file do
    priv_path("ca.pem")
  end

  defp priv_path(name) do
    Path.join([:code.priv_dir(:smtp_submit), "fake_tls", name])
  end

  @impl true
  def init(opts) do
    Process.flag(:trap_exit, true)

    with {:ok, listener} <-
           :gen_tcp.listen(0, [:binary, active: false, ip: {127, 0, 0, 1}, reuseaddr: true]),
         {:ok, {_, port}} <- :inet.sockname(listener) do
      server = self()
      acceptor = spawn_link(fn -> accept(listener, server) end)

      {:ok,
       %{
         listener: listener,
         acceptor: acceptor,
         port: port,
         config: %{
           tls: Keyword.get(opts, :tls, :starttls),
           certfile: Keyword.get(opts, :certfile, priv_path("localhost.pem")),
           keyfile: Keyword.get(opts, :keyfile, priv_path("localhost-key.pem")),
           chainfile: Keyword.get(opts, :chainfile, priv_path("intermediate.pem")),
           username: Keyword.get(opts, :username, "fake-user"),
           password: Keyword.get(opts, :password, "fake-password"),
           auth_mechanisms:
             opts
             |> Keyword.get(:auth_mechanisms, ["LOGIN", "PLAIN"])
             |> Enum.map(&String.upcase/1)
         },
         observer: Keyword.get(opts, :observer),
         scripts: [],
         commands: [],
         messages: []
       }}
    end
  end

  defp accept(listener, server) do
    case :gen_tcp.accept(listener) do
      {:ok, socket} ->
        # The acceptor owns the new socket, so it hands it to the peer itself.
        peer = GenServer.call(server, :start_peer)
        :ok = :gen_tcp.controlling_process(socket, peer)
        send(peer, {:socket, socket})
        accept(listener, server)

      {:error, :closed} ->
        :ok

      {:error, reason} ->
        exit(reason)
    end
  end

  @impl true
  def handle_call(:start_peer, _from, state) do
    # Peers are linked, so stopping the server drops every connection.
    server = self()
    config = state.config
    {:reply, spawn_link(fn -> Peer.wait(server, config) end), state}
  end

  def handle_call(:endpoint, _from, state) do
    {:reply, %{host: "localhost", port: state.port, cacertfile: ca_file()}, state}
  end

  def handle_call(:commands, _from, state) do
    {:reply, Enum.reverse(state.commands), state}
  end

  def handle_call(:messages, _from, state) do
    {:reply, Enum.reverse(state.messages), state}
  end

  def handle_call({:script, kind, action}, _from, state) do
    if kind in @kinds and valid_action?(action),
      do: {:reply, :ok, %{state | scripts: state.scripts ++ [{kind, action}]}},
      else: {:reply, {:error, :invalid_script}, state}
  end

  def handle_call({:command, record}, _from, state) do
    kind = if is_tuple(record), do: elem(record, 0), else: record
    notify(state, record)

    case Enum.find_index(state.scripts, &(elem(&1, 0) == kind)) do
      nil ->
        {:reply, nil, %{state | commands: [record | state.commands]}}

      index ->
        {{_, action}, scripts} = List.pop_at(state.scripts, index)
        {:reply, action, %{state | commands: [record | state.commands], scripts: scripts}}
    end
  end

  def handle_call({:accepted, message}, _from, state) do
    {:reply, :ok, %{state | messages: [message | state.messages]}}
  end

  @impl true
  def handle_cast(:closed, state) do
    notify(state, :closed)
    {:noreply, state}
  end

  @impl true
  # A fake that can no longer accept connections stops rather than leaving
  # clients to time out.
  def handle_info({:EXIT, acceptor, reason}, %{acceptor: acceptor} = state) do
    {:stop, {:acceptor_exited, reason}, state}
  end

  def handle_info({:EXIT, _peer, _reason}, state) do
    {:noreply, state}
  end

  @impl true
  def format_status(status) do
    Map.update(status, :state, nil, fn
      %{config: config} = state -> %{state | config: %{config | password: :redacted}}
      state -> state
    end)
  end

  @impl true
  def terminate(_reason, state) do
    :gen_tcp.close(state.listener)
    :ok
  end

  defp notify(%{observer: nil}, _event) do
    :ok
  end

  defp notify(%{observer: observer}, event) do
    send(observer, {:smtp_fake, self(), event})
  end

  defp valid_action?({:reply, text}) do
    is_binary(text)
  end

  defp valid_action?(action) do
    action in [:stall, :close]
  end
end
