defmodule UeberauthProcore.Mixfile do
  use Mix.Project

  def project do
    [app: :ueberauth_procore,
     version: "0.1.0",
     elixir: "~> 1.3",
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     description: description(),
     package: package(),
     deps: deps()]
  end

  # Configuration for the OTP application
  #
  # Type "mix help compile.app" for more information
  def application do
    [applications: [:logger, :oauth2, :ueberauth]]
  end

  # Dependencies can be Hex packages:
  #
  #   {:mydep, "~> 0.3.0"}
  #
  # Or git/path repositories:
  #
  #   {:mydep, git: "https://github.com/elixir-lang/mydep.git", tag: "0.1.0"}
  #
  # Type "mix help deps" for more examples and options
  defp deps do
    [{:ueberauth, "~> 0.4"},
     {:oauth2, "0.6.0"},
     {:ex_doc, "~> 0.14.0", only: :dev}]
  end

  defp description do
    """
    An Ueberauth strategy for using Procore (OAuth) authentication.
    """
  end

  defp package do
    [files: ["lib", "mix.exs", "README*", "LICENCE*"],
     maintainers: ["Gary Rennie", "Gabi Zuniga"],
     licenses: ["MIT"],
     links: %{"GitHub" => "https://github.com/voicelayer/ueberauth_procore",
              "Docs" => "https://hexdocs.pm/ueberauth_procore"}]
  end
end
