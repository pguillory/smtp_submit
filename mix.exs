defmodule SMTPSubmit.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/pguillory/smtp_submit"

  def project do
    [
      app: :smtp_submit,
      version: @version,
      elixir: "~> 1.18",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description:
        "A hardened SMTP submission client with strict TLS, phase deadlines and an " <>
          "outcome-unknown result, an RFC-conforming MIME builder, and a loopback fake server.",
      package: [licenses: ["MIT"], links: %{"GitHub" => @source_url}],
      source_url: @source_url
    ]
  end

  def application do
    [extra_applications: [:logger, :ssl, :public_key, :crypto]]
  end

  defp elixirc_paths(:test) do
    ["lib", "test/support"]
  end

  defp elixirc_paths(_env) do
    ["lib"]
  end

  defp deps do
    [
      # The SMTP protocol client. Pinned to 1.3.x: the worker reads its error
      # tuples, which a minor release could change.
      {:gen_smtp, "~> 1.3.0"}
    ]
  end
end
