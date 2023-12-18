defmodule Minisign do
  @moduledoc """
  Elixir implementation of the Minisign signature verification format.

  see https://jedisct1.github.io/minisign/
  """

  alias Minisign.PublicKey
  alias Minisign.Signature

  @type public_key_input :: String.t() | {:file, Path.t()} | PublicKey.t()
  @type signature_input :: String.t() | {:file, Path.t()} | Signature.t()
  @type message_input :: binary | {:file, Path.t()}
  @type reason :: :key_id_match | :signature | :global_signature

  @spec verify(message_input, signature_input, public_key_input) ::
          :ok | {:invalid, reason} | {:error, any}
  @doc """
  verifies a signature, returning `:ok` if the signature is valid.

  if the signature is invalid, returns an `:invalid` tuple indicating the
  reason why the signature failed to validate.

  if any of the inputs have failed, returns an `:error` tuple.

  For the key or signature inputs you may provide Base64 encoded strings, or a
  `{:file, path}` tuple to read from a file or a preparsed datastructure.

  For the message input, you may either provide the raw binary or, a `{:file, path}`
  tuple to read the message from the file.
  """
  def verify(message, signature, public_key) do
    with {:ok, public_key} <- marshal(public_key, PublicKey),
         {:ok, signature} <- marshal(signature, Signature),
         {:ok, message} <- marshal(message, nil) do
      do_verify(public_key, signature, message)
    end
  end

  @spec verify!(message_input, signature_input, public_key_input) :: boolean
  @doc """
  verifies a signature, and raises if any of the inputs are invalid.
  """
  def verify!(message, signature, public_key) do
    case verify(message, signature, public_key) do
      :ok -> true
      :invalid -> false
      {:error, error} -> raise error
    end
  end

  defp marshal({:file, file}, module), do: marshal(File.read(file), module)
  defp marshal(string, nil) when is_binary(string), do: {:ok, string}
  defp marshal(string, module) when is_binary(string), do: module.parse(string)
  defp marshal(%module{} = datatype, module), do: {:ok, datatype}

  # everything else raises argument error.

  defp do_verify(pk, sg, msg) do
    digest = :crypto.hash(:blake2b, msg)

    cond do
      sg.key_id != pk.key_id ->
        {:invalid, :key_id_match}

      !:crypto.verify(:eddsa, :none, {:digest, digest}, sg.signature, [pk.key, :ed25519]) ->
        {:invalid, :signature}

      !:crypto.verify(
        :eddsa,
        :none,
        {:digest, sg.signature <> sg.trusted_comment},
        sg.global_signature,
        [pk.key, :ed25519]
      ) ->
        {:invalid, :global_signature}

      true ->
        :ok
    end
  rescue
    a in ArgumentError -> {:error, a}
  end
end
