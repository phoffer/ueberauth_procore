# UeberauthProcore

This is a Procore adapter for Überauth. The implementation is largely taken from
https://github.com/ueberauth/ueberauth_github

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed as:

  1. Add `ueberauth_procore` to your list of dependencies in `mix.exs`:

    ```elixir
    def deps do
      [{:ueberauth_procore, "~> 0.1.0"}]
    end
    ```

  2. Ensure `ueberauth_procore` is started before your application:

    ```elixir
    def application do
      [applications: [:ueberauth_procore]]
    end
    ```

  3. Add Procore to your Überauth configuration:

    ```elixir
    config :ueberauth, Ueberauth,
      providers: [
        procore: {Ueberauth.Strategy.Procore, []}
      ]
    ```

  4. Update your provider configuration:

    ```elixir
    config :ueberauth, Ueberauth.Strategy.Procore.OAuth,
      client_id: System.get_env("PROCORE_CLIENT_ID"),
      client_secret: System.get_env("PROCORE_CLIENT_SECRET"),
      redirect_uri: "https://someproxy.com" #optional
    ```

