defmodule SMTPSubmit.Worker do
  # Internal to SMTPSubmit: the process that owns one connection.
  @moduledoc false

  alias SMTPSubmit.Error

  # Runs one open/deliver/close in a fresh process that owns the socket and
  # returns :ok (accepted) or {:error, %Error{}}. The caller enforces each
  # phase's deadline and kills the worker when one expires; a watcher kills it
  # if the caller dies. The worker reports acceptance before cleanup, so a slow
  # or failing close cannot change the result.
  def run(client, options, envelope, timeouts) do
    caller = self()
    ref = make_ref()

    {pid, monitor} =
      :erlang.spawn_opt(fn -> work(caller, ref, client, options, envelope) end, [:monitor])

    # Until :go the worker watches the caller itself, so a caller killed before
    # the watcher exists still takes the worker down.
    spawn(fn -> watch(caller, pid) end)
    send(pid, {ref, :go})
    state = %{pid: pid, monitor: monitor, ref: ref, timeouts: timeouts}

    {result, worker} =
      case await_open(state) do
        :opened -> await_delivery(state)
        failed -> failed
      end

    if worker == :alive, do: await_cleanup(state)
    flush(ref)
    result
  end

  defp await_open(state) do
    %{ref: ref, monitor: monitor, pid: pid, timeouts: timeouts} = state

    receive do
      {^ref, :opened} ->
        :opened

      {^ref, {:open_failed, error}} ->
        {{:error, error}, :alive}

      {:DOWN, ^monitor, :process, ^pid, _reason} ->
        {{:error, %Error{code: :internal, stage: :open}}, :down}
    after
      timeouts.open_ms ->
        kill(state)
        {{:error, %Error{code: :timeout, stage: :open, timeout_ms: timeouts.open_ms}}, :down}
    end
  end

  defp await_delivery(state) do
    %{ref: ref, monitor: monitor, pid: pid, timeouts: timeouts} = state

    receive do
      {^ref, :accepted} ->
        {:ok, :alive}

      {^ref, {:deliver_failed, error}} ->
        {{:error, error}, :alive}

      {:DOWN, ^monitor, :process, ^pid, _reason} ->
        {{:error, %Error{code: :internal, stage: :deliver, outcome_unknown?: true}}, :down}
    after
      timeouts.deliver_ms ->
        kill(state)

        error = %Error{
          code: :timeout,
          stage: :deliver,
          timeout_ms: timeouts.deliver_ms,
          outcome_unknown?: true
        }

        {{:error, error}, :down}
    end
  end

  # The result is already latched: give cleanup its own short budget, then kill
  # the worker so nothing lingers.
  defp await_cleanup(%{monitor: monitor, pid: pid} = state) do
    receive do
      {:DOWN, ^monitor, :process, ^pid, _reason} -> :ok
    after
      state.timeouts.cleanup_ms -> kill(state)
    end
  end

  defp kill(%{pid: pid, monitor: monitor}) do
    Process.exit(pid, :kill)

    receive do
      {:DOWN, ^monitor, :process, ^pid, _reason} -> :ok
    end
  end

  defp flush(ref) do
    receive do
      {^ref, _message} -> flush(ref)
    after
      0 -> :ok
    end
  end

  defp watch(caller, worker) do
    caller_monitor = Process.monitor(caller)
    worker_monitor = Process.monitor(worker)

    receive do
      {:DOWN, ^caller_monitor, :process, _, _} -> Process.exit(worker, :kill)
      {:DOWN, ^worker_monitor, :process, _, _} -> :ok
    end
  end

  defp work(caller, ref, client, options, envelope) do
    # The options hold the password. Keep them out of process inspection, and
    # catch every failure so the runtime never logs a crash with its arguments.
    # gen_smtp logs some TLS upgrade failures itself, with reasons that can
    # name the host or CA file, so this process logs nothing at all.
    Process.flag(:sensitive, true)
    Logger.put_process_level(self(), :none)
    caller_monitor = Process.monitor(caller)

    receive do
      {^ref, :go} -> Process.demonitor(caller_monitor, [:flush])
      {:DOWN, ^caller_monitor, :process, _, _} -> exit(:normal)
    end

    case open(client, options) do
      {:ok, socket} ->
        send(caller, {ref, :opened})
        send(caller, {ref, deliver(client, socket, envelope)})
        close(client, socket)

      {:error, error} ->
        send(caller, {ref, {:open_failed, error}})
    end
  end

  defp open(client, options) do
    case client.open([{:trace_fun, &trace/2} | options]) do
      {:ok, socket} -> {:ok, socket}
      failure -> {:error, open_error(failure)}
    end
  catch
    # gen_smtp's reply reader raises on some malformed replies from the
    # server, which is external input; nothing was sent yet.
    _kind, _reason -> {:error, %Error{code: :protocol, stage: :open}}
  end

  defp open_error({:error, _type, {:permanent_failure, _host, :auth_failed}}) do
    codes = :auth_reply_codes |> Process.get([]) |> Enum.reverse()

    %Error{
      code: :auth_failed,
      stage: :open,
      reply_code: List.last(codes),
      auth_reply_codes: codes
    }
  end

  defp open_error({:error, _type, {_failure, _host, reason}})
       when reason in [:tls_failed, :ssl_not_started] do
    %Error{code: :tls_failed, stage: :open}
  end

  defp open_error({:error, _type, {failure, _host, reply}})
       when failure in [:permanent_failure, :temporary_failure] and is_binary(reply) do
    %Error{code: :rejected, stage: :open, reply_code: reply_code(reply)}
  end

  defp open_error({:error, _type, {:missing_requirement, _host, :tls}}) do
    %Error{code: :tls_unavailable, stage: :open}
  end

  defp open_error({:error, _type, {:missing_requirement, _host, :auth}}) do
    %Error{code: :auth_unavailable, stage: :open}
  end

  defp open_error({:error, _type, {:unexpected_response, _host, _lines}}) do
    %Error{code: :protocol, stage: :open}
  end

  # An implicit-TLS handshake failure surfaces as a failed connect.
  defp open_error({:error, _type, {:network_failure, _host, {:error, {:tls_alert, _alert}}}}) do
    %Error{code: :tls_failed, stage: :open}
  end

  defp open_error({:error, _type, {:network_failure, _host, _reason}}) do
    %Error{code: :network, stage: :open}
  end

  defp open_error(_failure) do
    %Error{code: :internal, stage: :open}
  end

  # gen_smtp 1.3's traces of a refused AUTH attempt (do_AUTH_each), each with the
  # server's reply as a binary or {ok, Binary}. Only a well-formed 4xx or 5xx code is
  # kept, in this worker's process dictionary. Every other trace is ignored unread:
  # some carry the options, password included.
  @auth_refusals [
    ~c"authentication rejected: ~s~n",
    ~c"got ~s~n",
    ~c"username rejected: ~s",
    ~c"password rejected: ~s",
    ~c"authentication rejected ~p~n"
  ]

  defp trace(format, [reply]) when format in @auth_refusals do
    reply =
      case reply do
        {:ok, reply} -> reply
        reply -> reply
      end

    case reply_code(reply) do
      code when code in 400..599 ->
        Process.put(:auth_reply_codes, [code | Process.get(:auth_reply_codes, [])])

      _ ->
        :ok
    end
  end

  defp trace(_format, _args) do
    :ok
  end

  defp deliver(client, socket, envelope) do
    case client.deliver(socket, envelope) do
      {:ok, _receipt} -> :accepted
      {:error, failure} -> {:deliver_failed, deliver_error(failure)}
    end
  catch
    # gen_smtp raises on some malformed replies from the server, which is
    # external input; the message may already have been accepted.
    _kind, _reason ->
      {:deliver_failed, %Error{code: :protocol, stage: :deliver, outcome_unknown?: true}}
  end

  # gen_smtp accepts only a final "250 " reply. A bare "250", a multiline 250,
  # a malformed code such as "4ab" or any other non-refusal means the server
  # may have taken the message, so only a well-formed 4xx or 5xx reply is a
  # definite refusal.
  defp deliver_error({failure, reply})
       when failure in [:permanent_failure, :temporary_failure] and is_binary(reply) do
    case reply_code(reply) do
      code when code in 400..599 -> %Error{code: :rejected, stage: :deliver, reply_code: code}
      code -> unknown(:protocol, code)
    end
  end

  defp deliver_error({:unexpected_response, _lines}) do
    unknown(:protocol, nil)
  end

  defp deliver_error({:network_failure, _reason}) do
    unknown(:network, nil)
  end

  defp deliver_error(_failure) do
    unknown(:internal, nil)
  end

  defp unknown(code, reply_code) do
    %Error{code: code, stage: :deliver, reply_code: reply_code, outcome_unknown?: true}
  end

  defp reply_code(<<a, b, c, _::binary>>) when a in ?2..?5 and b in ?0..?9 and c in ?0..?9 do
    String.to_integer(<<a, b, c>>)
  end

  defp reply_code(_reply) do
    nil
  end

  defp close(client, socket) do
    client.close(socket)
  catch
    # The result is already latched; a failing close can't change it, and a
    # crash report here would carry the socket and options.
    _kind, _reason -> :ok
  end
end
