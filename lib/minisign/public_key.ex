defmodule Minisign.PublicKey do
  @doc """
  Public key datastructure for minisign.

  fields:

  - `:algorithm`: always `:Ed`
  - `:key_id`: 8 byte key id
  - `:key`: 32 byte public key

  see https://jedisct1.github.io/minisign/#public-key-format
  """

  defstruct [:algorithm, :key_id, :key]

  alias Minisign.ParseError

  @type t :: %__MODULE__{
          algorithm: :Ed,
          key_id: <<_::8>>,
          key: <<_::256>>
        }

  @spec parse(String.t()) :: {:ok, t} | {:error, ParseError.t()}
  @doc """
  parses a public key string.  Note that the untrusted comment field is considered
  optional, as many sources will include a public key as a simple base64 hash with
  no comment.
  """
  def parse(string) do
    string
    |> String.split("\n")
    |> parse_parts()
  end

  @spec parse!(String.t()) :: t
  @doc """
  parses a public key string, or raises if the string is not a public key representation

  see `parse/1`
  """
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
