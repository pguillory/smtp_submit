defmodule SMTPSubmit.Test.TracedRefusalClient do
  @moduledoc false
  # A client whose open/1 reports the AUTH refusals gen_smtp 1.3's do_AUTH_each
  # traces (for paths the fake can't show over a socket: a refused AUTH LOGIN, a
  # refused username, CRAM-MD5's own refusal, a PLAIN reply read error), then fails
  # as gen_smtp does when every mechanism was refused. Unlike the fake-server tests,
  # these can't catch a gen_smtp release that changes those traces.

  def open(options) do
    trace = Keyword.fetch!(options, :trace_fun)
    trace.(~c"Auth types: ~p~n", [~c"LOGIN PLAIN"])
    trace.(~c"got ~s~n", ["504 5.5.4 Unrecognized authentication type\r\n"])
    trace.(~c"username rejected: ~s", ["535 5.7.8 Unknown user\r\n"])
    trace.(~c"got ~s~n", ["334 VXNlcm5hbWU6\r\n"])
    trace.(~c"password rejected: ~s", ["454 4.7.0 Try again later\r\n"])
    trace.(~c"authentication rejected ~p~n", [{:error, :closed}])

    trace.(~c"authentication rejected ~p~n", [
      {:ok, "534 5.7.9 Application-specific password required\r\n"}
    ])

    trace.(~c"authentication rejected: ~s~n", ["535 5.7.8 Bad credentials\r\n"])
    trace.(~c"TLS not requested ~p~n", [options])
    {:error, :no_more_hosts, {:permanent_failure, ~c"smtp.example.test", :auth_failed}}
  end

  def deliver(_socket, _email) do
    raise "not reached"
  end

  def close(_socket) do
    :ok
  end
end
