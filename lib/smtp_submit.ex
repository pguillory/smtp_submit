defmodule SMTPSubmit do
  @moduledoc """
  A hardened SMTP submission client: one authenticated send per call over
  verified TLS, built on the unmodified `gen_smtp` client.

  * `send/4` sends a finished message to an explicit envelope.
  * `deliver/2` builds a `SMTPSubmit.Email` into a MIME message and sends it
    to its To, Cc and Bcc recipients, without a Bcc header.

  Both return `:ok` once the server accepted the message,
  `{:error, %SMTPSubmit.InvalidEmail{}}` before any connection, or
  `{:error, %SMTPSubmit.Error{}}`. An `SMTPSubmit.Error` with
  `outcome_unknown?: true` means the server may have accepted the message:
  never resend it automatically.

  Each call opens a connection in a short-lived worker that owns the socket,
  delivers once and closes. There are no retries, reconnects, pools or MX
  lookups. The worker dies with the caller and is killed at each deadline, so
  no work outlives the call.

  ## Config

  A map with:

  * `:host`, `:port` - the submission server
  * `:username`, `:password` - credentials; AUTH is required
  * `:tls` - `:implicit` (TLS from the first byte) or `:starttls` (a
    mandatory upgrade before AUTH). Default: `:implicit` on port 465 (RFC
    8314), `:starttls` on any other port. There is no plaintext mode.
  * `:cacertfile` - a CA file to trust instead of the OS store
  * `:hostname` - the EHLO name, a plain domain or address literal; default
    gen_smtp's guess at this host's FQDN
  * `:open_timeout` - connect, greeting, EHLO, STARTTLS and AUTH; default 120 000 ms
  * `:deliver_timeout` - MAIL through the final reply; default 240 000 ms
  * `:cleanup_timeout` - QUIT and close; default 5 000 ms
  * `:connect_timeout` - the TCP connect and, for implicit TLS, the
    handshake (inside open); default 15 000 ms
  * `:client` - a module with `gen_smtp_client`'s `open/1`, `deliver/2` and
    `close/1`; default `:gen_smtp_client`. For tests and wrappers. Its `open/1`
    options include a `:trace_fun`, which yields `auth_reply_codes`.
  """

  alias SMTPSubmit.Email
  alias SMTPSubmit.InvalidEmail
  alias SMTPSubmit.Worker

  @implicit_tls_port 465
  @default_open_timeout 120_000
  @default_deliver_timeout 240_000
  @default_cleanup_timeout 5_000
  @default_connect_timeout 15_000

  # gen_smtp merges {depth, 0} into its TLS options for both implicit TLS and
  # the STARTTLS upgrade, which rejects any chain with an intermediate CA:
  # every real provider. 10 is OTP's default.
  @tls_max_chain_depth 10

  @required_keys [:host, :port, :username, :password]

  @type result :: :ok | {:error, SMTPSubmit.Error.t() | InvalidEmail.t()}

  @doc """
  Sends `message`, finished RFC 5322 text, from `from` to `recipients` (bare
  addresses). The message must be 7-bit with CRLF line endings, no NUL and
  no line over 998 bytes; one trailing CRLF is dropped, since the DATA terminator
  adds its own. Exact duplicate recipients are sent once.
  """
  @spec send(map(), String.t(), [String.t()], binary()) :: result()
  def send(config, from, recipients, message) do
    config = config!(config)

    with :ok <- envelope_addresses(from, recipients),
         {:ok, message} <- check_message(message) do
      envelope = {from, Enum.uniq(recipients), message}
      client = Map.get(config, :client, :gen_smtp_client)
      Worker.run(client, client_options(config), envelope, timeouts(config))
    end
  end

  @doc """
  Builds `email` with `SMTPSubmit.Email.build/2` and sends it from its From
  address to every To, Cc and Bcc address. Bcc is never written to the
  message.
  """
  @spec deliver(map(), Email.t()) :: result()
  def deliver(config, email) do
    config = config!(config)

    # Not an Email is a caller bug. A FunctionClauseError would print the
    # arguments, config and password included, so it raises fixed text instead.
    if not is_struct(email, Email),
      do: raise(ArgumentError, "deliver/2 takes an SMTPSubmit.Email")

    with {:ok, message} <- Email.build(email),
         {:ok, from, recipients} <- Email.envelope(email) do
      send(config, from, recipients, message)
    end
  end

  # A bad config is a caller bug, so it raises, with fixed text: the default
  # FunctionClauseError would print the map, password included.
  defp config!(config) do
    if valid_config?(config) do
      config
    else
      raise ArgumentError,
            "an SMTPSubmit config needs :host (string), :port (integer), :username and " <>
              ":password; :tls must be :implicit or :starttls, and :hostname a domain name"
    end
  end

  defp valid_config?(config) do
    is_map(config) and Enum.all?(@required_keys, &Map.has_key?(config, &1)) and
      is_binary(config.host) and is_integer(config.port) and
      Map.get(config, :tls, :default) in [:default, :implicit, :starttls] and
      hostname?(Map.get(config, :hostname))
  end

  # The EHLO name goes on the command line as is, so it must be a plain domain
  # or address literal, never anything that could end the line.
  defp hostname?(nil) do
    true
  end

  defp hostname?(hostname) do
    is_binary(hostname) and Regex.match?(~r/\A[A-Za-z0-9.:\[\]-]{1,255}\z/, hostname)
  end

  defp envelope_addresses(from, recipients) do
    cond do
      not Email.valid_address?(from) ->
        {:error, %InvalidEmail{reason: :invalid_address, field: :from}}

      not is_list(recipients) or recipients == [] ->
        {:error, %InvalidEmail{reason: :no_recipients, field: :recipients}}

      not Enum.all?(recipients, &Email.valid_address?/1) ->
        {:error, %InvalidEmail{reason: :invalid_address, field: :recipients}}

      true ->
        :ok
    end
  end

  defp check_message(message) when is_binary(message) do
    message =
      if String.ends_with?(message, "\r\n"),
        do: binary_part(message, 0, byte_size(message) - 2),
        else: message

    lines = :binary.split(message, "\r\n", [:global])

    valid? =
      message != "" and
        Enum.all?(lines, fn line ->
          byte_size(line) <= 998 and
            Enum.all?(:binary.bin_to_list(line), &(&1 not in [0, ?\r, ?\n] and &1 <= 0x7F))
        end)

    if valid?,
      do: {:ok, message},
      else: {:error, %InvalidEmail{reason: :invalid_message, field: :message}}
  end

  defp check_message(_message) do
    {:error, %InvalidEmail{reason: :invalid_message, field: :message}}
  end

  defp timeouts(config) do
    %{
      open_ms: Map.get(config, :open_timeout, @default_open_timeout),
      deliver_ms: Map.get(config, :deliver_timeout, @default_deliver_timeout),
      cleanup_ms: Map.get(config, :cleanup_timeout, @default_cleanup_timeout)
    }
  end

  defp client_options(config) do
    tls = tls_options(config.host, Map.get(config, :cacertfile))

    implicit? =
      case Map.get(config, :tls) do
        nil -> config.port == @implicit_tls_port
        mode -> mode == :implicit
      end

    mode =
      if implicit?,
        do: [ssl: true, tls: :never, sockopts: tls],
        else: [ssl: false, tls: :always, tls_options: tls]

    hostname =
      case Map.get(config, :hostname) do
        nil -> []
        hostname -> [hostname: hostname]
      end

    [
      relay: String.to_charlist(config.host),
      port: config.port,
      username: config.username,
      password: config.password,
      auth: :always,
      retries: 0,
      no_mx_lookups: true,
      timeout: Map.get(config, :connect_timeout, @default_connect_timeout)
    ] ++ hostname ++ mode
  end

  # The same policy for the implicit-TLS socket and the STARTTLS upgrade. The
  # upgrade has no host argument, so SNI names the host explicitly; for an IP,
  # OTP checks the IP SAN against the peer address instead. With implicit TLS
  # OTP still sends an IP host as SNI: `server_name_indication: :disable`
  # would also turn off the hostname check, and gen_smtp needs a string relay,
  # so that narrow RFC 6066 deviation stays. OTP's own TLS logging is off
  # because its alerts name the host and certificate SANs.
  defp tls_options(host, cacertfile) do
    trust =
      case cacertfile do
        nil -> [cacerts: :public_key.cacerts_get()]
        path -> [cacertfile: String.to_charlist(path)]
      end

    sni =
      case :inet.parse_address(String.to_charlist(host)) do
        {:ok, _address} -> []
        _ -> [server_name_indication: String.to_charlist(host)]
      end

    [
      verify: :verify_peer,
      versions: [:"tlsv1.3", :"tlsv1.2"],
      depth: @tls_max_chain_depth,
      customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)],
      log_level: :none
    ] ++ trust ++ sni
  end
end
