defmodule DeoxysIITest do
  use ExUnit.Case, async: true
  import Bitwise
  alias DeoxysII
  alias DeoxysII.ByteArray

  doctest DeoxysII

  @testdata Path.join([__DIR__, "testdata"])

  defmodule OfficialTestVector do
    defstruct [:name, :key, :nonce, :ad, :msg, :sealed]
  end

  test "kat" do
    filepath = Path.join(@testdata, "Deoxys-II-256-128.json")
    {:ok, data} = File.read!(filepath) |> Jason.decode()

    key = Base.decode64!(data["Key"])
    nonce = Base.decode64!(data["Nonce"])
    assert byte_size(nonce) == 15

    msg = Base.decode64!(data["MsgData"])
    ad = Base.decode64!(data["AADData"])
    x = DeoxysII.new(key)

    hex =
      for l <- x.derived_k do
        ByteArray.get(l) |> Base.encode16(case: :lower)
      end
      |> Enum.join("")

    digest = :crypto.hash(:sha256, hex) |> Base.encode16(case: :lower)
    assert digest == "a3b7c1a32e37360edbbedc4f9f3064f08ab1ebf69a3b987b346635cb33ed56fa"

    off = 0

    Enum.each(data["KnownAnswers"], fn row ->
      pt_len = row["Length"]
      m = binary_part(msg, 0, pt_len)
      a = binary_part(ad, 0, pt_len)

      expected_dst = Base.decode64!(row["Ciphertext"]) <> Base.decode64!(row["Tag"])
      expected_ciphertext = binary_part(expected_dst, off, byte_size(expected_dst) - off)

      # Encryption test
      dst_size = pt_len + DeoxysII.tag_size()
      ciphertext = DeoxysII.encrypt(x, nonce, a, m)

      assert dst_size == byte_size(ciphertext)
      c = binary_part(ciphertext, off, byte_size(ciphertext) - off)

      assert binary_part(c, 0, pt_len) == binary_part(expected_ciphertext, 0, pt_len)

      # Decryption test
      result = DeoxysII.decrypt(x, nonce, a, c)
      assert result

      # Test malformed ciphertext (or tag)
      bad_ciphertext = :binary.copy(c)

      bad_ciphertext =
        :binary.part(bad_ciphertext, 0, pt_len) <>
          <<bxor(:binary.at(c, pt_len), 0x23)>> <>
          :binary.part(c, pt_len + 1, byte_size(c) - pt_len - 1)

      refute DeoxysII.decrypt(x, nonce, a, bad_ciphertext)

      # Test malformed AD
      if pt_len > 0 do
        bad_ad = :binary.copy(a)

        bad_ad =
          :binary.part(bad_ad, 0, pt_len - 1) <>
            <<bxor(:binary.at(a, pt_len - 1), 0x23)>> <>
            :binary.part(a, pt_len, byte_size(a) - pt_len)

        refute DeoxysII.decrypt(x, nonce, bad_ad, c)
      end
    end)
  end

  test "official" do
    filepath = Path.join(@testdata, "Deoxys-II-256-128-official-20190608.json")
    {:ok, data} = File.read!(filepath) |> Jason.decode()

    Enum.each(data, fn row ->
      t = %OfficialTestVector{
        name: row["Name"],
        key: Base.decode16!(row["Key"], case: :lower),
        nonce: Base.decode16!(row["Nonce"], case: :lower),
        ad:
          if(row["AssociatedData"],
            do: Base.decode16!(row["AssociatedData"], case: :lower),
            else: <<>>
          ),
        msg: if(row["Message"], do: Base.decode16!(row["Message"], case: :lower), else: <<>>),
        sealed: Base.decode16!(row["Sealed"], case: :lower)
      }

      x = DeoxysII.new(t.key)

      # Verify encryption matches
      ciphertext = DeoxysII.encrypt(x, t.nonce, t.ad, t.msg)
      assert ciphertext == t.sealed

      # Verify decryption matches
      result = DeoxysII.decrypt(x, t.nonce, t.ad, t.sealed)
      assert result
      assert result == t.msg
    end)
  end
end
