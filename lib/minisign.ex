defmodule Minisign do

  alias Minisign.PublicKey
  alias Minisign.Signature

  @type public_key_input :: String.t | {:file, Path.t} | PublicKey.t
  @type signature_input :: String.t | {:file, Path.t} | Signature.t
  @type message_input :: String.t | {:file, Path.t}
  @type reason :: :key_id_match | :signature | :global_signature

  @spec verify(public_key_input, signature_input, message_input) :: :ok | {:invalid, reason} | {:error, any}
  def verify(public_key, signature, message) do
    with {:ok, public_key} <- marshal(public_key, PublicKey),
         {:ok, signature} <- marshal(signature, Signature),
         {:ok, message} <- marshal(message, nil) do
      do_verify(public_key, signature, message)
    end
  end

  @spec verify!(public_key_input, signature_input, message_input) :: boolean
  def verify!(public_key, signature, message) do
    case verify(public_key, signature, message) do
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
      !:crypto.verify(:eddsa, :none, {:digest, sg.signature <> sg.trusted_comment}, sg.global_signature, [pk.key, :ed25519]) ->
        {:invalid, :global_signature}
      true ->
        :ok
    end
  end
end
