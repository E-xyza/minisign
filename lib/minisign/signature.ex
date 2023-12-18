defmodule Minisign.Signature do
  defstruct [:algorithm, :trusted_comment, :key_id, :signature, :global_signature]

  alias Minisign.ParseError

  @type t :: %__MODULE__{
          algorithm: :Ed,
          trusted_comment: String.t(),
          key_id: <<_::8>>,
          signature: <<_::256>>,
          global_signature: <<_::256>>
        }

  def parse(string) do
    string
    |> String.split("\n")
    |> get_parts
  end

  def parse!(string) do
    case parse(string) do
      {:ok, Signature} -> Signature
      {:error, reason} -> raise reason
    end
  end

  defp get_parts([
         "untrusted comment: " <> _,
         encoded_signature,
         "trusted comment: " <> trusted_comment,
         encoded_global_signature | _
       ]) do
    with {{:ok, <<"ED", key_id::binary-size(8), signature::binary-size(64)>>}, :s} <-
           {Base.decode64(encoded_signature), :s},
         {{:ok, <<global_signature::binary-size(64)>>}, :g} <- {Base.decode64(encoded_global_signature), :g} do
      {:ok, %__MODULE__{
        algorithm: :ED,
        trusted_comment: trusted_comment,
        key_id: key_id,
        signature: signature,
        global_signature: global_signature
      }}
    else
      {:error, :s} ->
        {:error, %ParseError{comment: "Invalid base64 encoding of signature", parser: __MODULE__}}

      {:error, :g} ->
        {:error,
         %ParseError{comment: "Invalid base64 encoding of global signature", parser: __MODULE__}}

      {{:ok, _}, :s} ->
        {:error, %ParseError{comment: "Invalid signature", ref: true, parser: __MODULE__}}

      {{:ok, g}, :g} ->
        g |> dbg(limit: 25)
        {:error, %ParseError{comment: "Invalid global signature", ref: true, parser: __MODULE__}}
    end
  end

  defp get_parts(_), do: {:error, %ParseError{comment: "Invalid format", parser: __MODULE__}}
end
