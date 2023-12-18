defmodule Minisign.PublicKey do
  defstruct [:algorithm, :key_id, :key]

  alias Minisign.ParseError

  @type t :: %__MODULE__{
          algorithm: :Ed,
          key_id: <<_::8>>,
          key: <<_::256>>
        }

  @spec parse(String.t()) :: {:ok, t} | {:error, ParseError.t()}
  def parse(string) do
    string
    |> String.split("\n")
    |> parse_parts()
  end

  def parse!(string) do
    case parse(string) do
      {:ok, private_key} -> private_key
      {:error, reason} -> raise reason
    end
  end

  defp parse_parts(["untrusted comment:" <> _ | rest]), do: parse(rest)

  defp parse_parts([rest]), do: parse_key(rest)

  defp parse_parts(_),
    do: {:error, %ParseError{comment: "Invalid format", ref: true, parser: __MODULE__}}

  defp parse_key(key) do
    case Base.decode64(key) do
      :error ->
        {:error, %ParseError{comment: "Invalid base64 encoding of key", parser: __MODULE__}}

      {:ok, <<"Ed", key_id::binary-size(8), key::binary-size(32)>>} ->
        {:ok, %__MODULE__{algorithm: :Ed, key_id: key_id, key: key}}

      {:ok, _} ->
        {:error, %ParseError{comment: "Invalid encoding", ref: true, parser: __MODULE__}}
    end
  end
end
