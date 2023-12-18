defmodule Minisign.MixProject do
  use Mix.Project

  def project do
    [
      app: :minisign,
      version: "0.1.0",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      package: package(),
      docs: docs()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      description: "Minisign library",
      licenses: ["MIT"],
      # we need to package the zig BEAM adapters and the c include files as a part
      # of the hex packaging system.
      files: ~w[lib mix.exs README* LICENSE* VERSIONS*],
      links: %{
        "GitHub" => "https://github.com/E-xyza/minisign",
        "Minisign" => "https://jedisct1.github.io/minisign/"
      }
    ]
  end

  defp docs do
    [
      main: "Minisign",
      extras: ["README.md"]
    ]
  end
end
