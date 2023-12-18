defmodule Minisign.ParseError do
  @moduledoc false
  defexception [:comment, :parser, :ref]

  alias Minisign.Signature
  alias Minisign.PublicKey

  @type t :: %__MODULE__{
          comment: String.t(),
          ref: boolean,
          parser: Signature | PublicKey
        }

  def message(error) do
    "Error parsing #{unit(error)}: #{error.comment}#{ref_str(error)}"
  end

  defp unit(%{parser: Signature}), do: "Signature"
  defp unit(%{parser: PublicKey}), do: "public key"

  defp ref_str(%{ref: true, parser: PublicKey}),
    do: " (see: https://jedisct1.github.io/minisign/#public-key-format)"

  defp ref_str(%{ref: true, parser: Signature}),
    do: " (see: https://jedisct1.github.io/minisign/#signature-format)"
end
