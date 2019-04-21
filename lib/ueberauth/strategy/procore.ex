defmodule Ueberauth.Strategy.Procore do
  @moduledoc """
  Provides an Ueberauth strategy for authenticating with Procore.

  ### Setup

  Create an application in Procore for you to use.

  Include the provider in your configuration for Ueberauth

      config :ueberauth, Ueberauth,
        providers: [
          procore: { Ueberauth.Strategy.Procore, [] }
        ]

  Then include the configuration for Procore.

      config :ueberauth, Ueberauth.Strategy.Procore.OAuth,
        client_id: System.get_env("PROCORE_CLIENT_ID"),
        client_secret: System.get_env("PROCORE_CLIENT_SECRET"),
        redirect_uri: "https://someproxy.com" #optional

  The `redirect_uri` configuration option is intended for proxies due to
  Procore requiring an HTTPS callback URL.
  """
  use Ueberauth.Strategy, oauth2_module: Ueberauth.Strategy.Procore.OAuth

  alias Ueberauth.Auth.{Info, Credentials, Extra}
  alias Ueberauth.Strategy.Helpers

  @doc """
  Handles the initial redirect to the Procore authentication page.
  """
  def handle_request!(conn) do
    opts = [redirect_uri: redirect_uri(conn)]
    module = option(conn, :oauth2_module)
    Helpers.redirect!(conn, apply(module, :authorize_url!, [opts]))
  end

  @doc """
  Handles the callback from Procore. When there is a failure from Procore the
  failure is included in the `ueberauth_failure` struct. Otherwise the
  information returned from Procore is returned in the `Ueberauth.Auth` struct.
  """
  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    module = option(conn, :oauth2_module)
    token = apply(module, :get_token!, [[code: code, redirect_uri: redirect_uri(conn)]])

    if token.access_token == nil do
      Helpers.set_errors!(conn, [error(token.other_params["error"],
                                 token.other_params["error_description"])])
    else
      fetch_user(conn, token)
    end
  end

  @doc false
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  @doc """
  Cleans up the private area of the connection used for passing the raw Procore
  response around during the callback.
  """
  def handle_cleanup!(conn) do
    conn
    |> put_private(:procore_user, nil)
    |> put_private(:procore_token, nil)
  end

  @doc """
  Fetches the uid field from the Procore response. This is the id field for
  the user.
  """
  def uid(conn) do
    conn.private.procore_user["id"]
  end

  @doc """
  Includes the credentials from the Procore response.
  """
  def credentials(conn) do
    token = conn.private.procore_token

    %Credentials{
      token: token.access_token,
      refresh_token: token.refresh_token,
      expires_at: token.expires_at,
      token_type: token.token_type,
      expires: !!token.expires_at
    }
  end

  @doc """
  Fetches the fields to populate the info section of the `Ueberauth.Auth`
  struct.
  """
  def info(conn) do
    user = conn.private.procore_user

    %Info{
      name: user["name"],
      first_name: user["first_name"],
      last_name: user["last_name"],
      phone: user["business_phone"],
      email: user["email_address"]
    }
  end

  @doc """
  Stores the raw information (including the token) obtained from the Procore
  callback.
  """
  def extra(conn) do
    %Extra {
      raw_info: %{
        token: conn.private.procore_token,
        user: conn.private.procore_user
      }
    }
  end

  defp fetch_user(conn, token) do
    conn = put_private(conn, :procore_token, token)
    with {:ok, companies}    <- get_companies(token),
         [%{"id" => id} | _] = companies,
         {:ok, user}         <- get_me(token, id)
    do
      put_private(conn, :procore_user, user)
    else
      {:error, :unauthorized}                 -> set_errors!(conn, [error("token", "unauthorized")])
      {:error, %OAuth2.Error{reason: reason}} -> set_errors!(conn, [error("OAuth2", reason)])
      {:error, reason}                        -> set_errors!(conn, [error("OAuth2", reason)])
    end
  end

  defp option(conn, key) do
    Dict.get(Helpers.options(conn), key, Dict.get(default_options, key))
  end

  defp redirect_uri(conn) do
    option(conn, :redirect_uri) || Helpers.callback_url(conn)
  end

  defp get_companies(token) do
    case OAuth2.AccessToken.get(token, "/vapid/companies") do
      {:ok, %OAuth2.Response{status_code: 200, body: companies}} -> {:ok, companies}
      {:ok, %OAuth2.Response{status_code: 401, body: _body}}     -> {:error, :unauthorized}
      other                                                      -> {:error, other}
    end
  end

  defp get_me(token, id) do
    case OAuth2.AccessToken.get(token, "/vapid/companies/#{id}/me") do
      {:ok, %OAuth2.Response{status_code: 200, body: me}} -> {:ok, me}
      other                                               -> {:error, :no_user}
    end
  end
end
