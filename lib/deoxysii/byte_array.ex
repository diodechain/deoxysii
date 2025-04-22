defmodule DeoxysII.ByteArray do
  @moduledoc """
  Helper module for porting from Python. This is a stateful ByteArray using the Process dictionary.
  """
  def new(size) when is_integer(size) do
    new(:binary.copy(<<0>>, size))
  end

  def new(binary) when is_binary(binary) do
    ref = make_ref()
    Process.put({__MODULE__, ref}, binary)
    ref
  end

  def clone(ref) do
    new(get(ref))
  end

  def len(ref) do
    byte_size(get(ref))
  end

  def get(binary) when is_binary(binary) do
    binary
  end

  def get(ref) when is_reference(ref) do
    Process.get({__MODULE__, ref}) || raise "ByteArray #{inspect(ref)} not found"
  end

  def write(ref, offset, value) when is_integer(value) do
    write(ref, offset, <<value>>)
  end

  def write(ref, offset, other) when is_reference(other) do
    write(ref, offset, get(other))
  end

  def write(ref, offset, binary) when is_binary(binary) do
    data = get(ref)
    size = byte_size(data)

    prefix =
      if offset > 0 do
        binary_part(data, 0, offset)
      else
        ""
      end

    if byte_size(binary) + offset >= size do
      put(ref, prefix <> binary)
    else
      rest = binary_part(data, byte_size(binary) + offset, size - (byte_size(binary) + offset))
      put(ref, prefix <> binary <> rest)
    end
  end

  def getc(ref, offset) do
    binary_part(get(ref), offset, 1)
  end

  def getb(ref, offset) do
    <<byte>> = getc(ref, offset)
    byte
  end

  def enumerate(ref) do
    :binary.bin_to_list(get(ref))
    |> Enum.with_index()
    |> Enum.map(fn {x, i} -> {i, x} end)
  end

  @doc """
  a[start:stop]  # items start through stop-1
  a[start:]      # items start through the rest of the array
  a[:stop]       # items from the beginning through stop-1
  a[:]           # a copy of the whole array
  """
  def sub(ref, nil, nil) do
    clone(ref)
  end

  def sub(ref, nil, to) do
    sub(ref, 0, to)
  end

  def sub(ref, from, nil) do
    sub(ref, from, len(ref))
  end

  def sub(ref, from, to) do
    new(binary_part(get(ref), from, to - from))
  end

  def put(ref, data) do
    Process.put({__MODULE__, ref}, data)
  end

  def pop(ref) do
    data = get(ref)
    Process.delete({__MODULE__, ref})
    data
  end

  def clear() do
    for {__MODULE__, ref} <- Process.get_keys() do
      Process.delete({__MODULE__, ref})
    end
  end
end
