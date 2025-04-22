defmodule DeoxysII do
  import Bitwise

  @moduledoc """
  This work is derived from: https://github.com/oasisprotocol/deoxysii

  Copyright (c) 2019 Oasis Labs Inc. <info@oasislabs.com>

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
  BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
  ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
  CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
  """

  alias DeoxysII.ByteArray
  # Constants
  @block_size 16
  @rounds 16
  @tweak_size 16
  @tag_size 16
  def tag_size(), do: @tag_size
  @stk_size 16
  @stk_count @rounds + 1

  # Prefix constants
  # 0010
  @prefix_ad_block 0x2
  # 0110
  @prefix_ad_final 0x6
  # 0000
  @prefix_msg_block 0x0
  # 0100
  @prefix_msg_final 0x4
  # 0001
  @prefix_tag 0x1
  @prefix_shift 4

  defp xor_bytes(out, a, b, n) do
    ByteArray.write(
      out,
      0,
      :crypto.exor(
        ByteArray.sub(a, 0, n) |> ByteArray.pop(),
        ByteArray.sub(b, 0, n) |> ByteArray.pop()
      )
    )
  end

  defp encode_tag_tweak(out, prefix, block_nr) do
    ByteArray.write(out, 8, <<block_nr::unsigned-big-size(64)>>)
    prefix = prefix <<< @prefix_shift
    ByteArray.write(out, 0, <<prefix>>)
  end

  defp encode_enc_tweak(out, tag, block_nr) do
    # Create 8-byte block number
    tmp = ByteArray.new(<<block_nr::unsigned-big-size(64)>>)
    # Write tag at start
    ByteArray.write(out, 0, ByteArray.sub(tag, 0, min(ByteArray.len(tag), @tweak_size)))
    # Set high bit
    ByteArray.write(out, 0, ByteArray.getb(out, 0) ||| 0x80)
    # XOR with block number
    for i <- 0..7 do
      ByteArray.write(
        out,
        8 + i,
        bxor(ByteArray.getb(out, 8 + i), ByteArray.getb(tmp, i))
      )
    end
  end

  # RCONS table
  @rcons DeoxysII.Const.rcon()

  # AES encryption tables
  @te0 DeoxysII.Const.te0()
  @te1 DeoxysII.Const.te1()

  defp stk_shuffle(t) do
    ByteArray.write(
      t,
      0,
      <<ByteArray.getb(t, 1), ByteArray.getb(t, 6), ByteArray.getb(t, 11), ByteArray.getb(t, 12),
        ByteArray.getb(t, 5), ByteArray.getb(t, 10), ByteArray.getb(t, 15), ByteArray.getb(t, 0),
        ByteArray.getb(t, 9), ByteArray.getb(t, 14), ByteArray.getb(t, 3), ByteArray.getb(t, 4),
        ByteArray.getb(t, 13), ByteArray.getb(t, 2), ByteArray.getb(t, 7), ByteArray.getb(t, 8)>>
    )
  end

  defp lfsr2(t) do
    for {i, x} <- ByteArray.enumerate(t) do
      x7 = x >>> 7
      x5 = x >>> 5 &&& 1
      x = rem(x <<< 1 ||| bxor(x7, x5), 256)
      ByteArray.write(t, i, <<x>>)
    end
  end

  defp lfsr3(t) do
    for {i, x} <- ByteArray.enumerate(t) do
      x0 = x &&& 1
      x6 = x >>> 6 &&& 1
      x = x >>> 1 ||| bxor(x0, x6) <<< 7
      ByteArray.write(t, i, <<x>>)
    end
  end

  defp xor_rc(t, i) do
    rcon = elem(@rcons, i)

    rc =
      ByteArray.new(<<
        1,
        2,
        4,
        8,
        rcon,
        rcon,
        rcon,
        rcon,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0
      >>)

    xor_bytes(t, t, rc, 8)
  end

  defp stk_derive_k(key) do
    derived_k = for _ <- 1..@stk_count, do: ByteArray.new(@stk_size)

    # Tk2 = W2
    tk2 = ByteArray.sub(key, 16, 32)
    # Tk3 = W3
    tk3 = ByteArray.sub(key, nil, 16)

    # i == 0
    xor_bytes(Enum.at(derived_k, 0), tk2, tk3, @stk_size)
    xor_rc(Enum.at(derived_k, 0), 0)

    # i == 0 ... i == 16
    for i <- 1..@rounds do
      # Tk2(i+1) = h(LFSR2(Tk2(i)))
      lfsr2(tk2)
      stk_shuffle(tk2)

      # Tk3(i+1) = h(LFSR3(Tk3(i)))
      lfsr3(tk3)
      stk_shuffle(tk3)

      xor_bytes(Enum.at(derived_k, i), tk2, tk3, @stk_size)
      xor_rc(Enum.at(derived_k, i), i)
    end

    for ref <- derived_k do
      ByteArray.pop(ref)
    end
  end

  @te2 DeoxysII.Const.te2()
  @te3 DeoxysII.Const.te3()

  defp uint8(x) when is_integer(x) do
    band(x, 0xFF)
  end

  defp get_deep(list, [a, b]) do
    Enum.at(Enum.at(list, a), b)
  end

  defp bc_encrypt(ciphertext, derived_k, tweak, plaintext) do
    # Derive all the Sub-Tweak Keys.
    stks = derive_sub_tweak_keys(derived_k, tweak)

    # AddRoundTweakKey (AES -> AddRoundKey)
    tmp = ByteArray.sub(plaintext, nil, 16) |> ByteArray.pop()

    <<s0::unsigned-big-size(32), s1::unsigned-big-size(32), s2::unsigned-big-size(32),
      s3::unsigned-big-size(32)>> = tmp

    s0 = bxor(s0, get_deep(stks, [0, 0]))
    s1 = bxor(s1, get_deep(stks, [0, 1]))
    s2 = bxor(s2, get_deep(stks, [0, 2]))
    s3 = bxor(s3, get_deep(stks, [0, 3]))

    {s0, s1, s2, s3} =
      Enum.reduce(1..@rounds, {s0, s1, s2, s3}, fn i, {s0, s1, s2, s3} ->
        # SubBytes, ShiftRows, MixBytes (AES -> MixColumns),
        # AddRoundTweakKey (AES -> AddRoundKey).
        #
        # In AES-NI terms, this is *exactly* equivalent to AESENC (though
        # Intel's notation transposes ShiftRows, and SubBytes).
        t0 =
          elem(@te0, uint8(s0 >>> 24))
          |> bxor(elem(@te1, uint8(s1 >>> 16)))
          |> bxor(elem(@te2, uint8(s2 >>> 8)))
          |> bxor(elem(@te3, uint8(s3)))
          |> bxor(get_deep(stks, [i, 0]))

        t1 =
          elem(@te0, uint8(s1 >>> 24))
          |> bxor(elem(@te1, uint8(s2 >>> 16)))
          |> bxor(elem(@te2, uint8(s3 >>> 8)))
          |> bxor(elem(@te3, uint8(s0)))
          |> bxor(get_deep(stks, [i, 1]))

        t2 =
          elem(@te0, uint8(s2 >>> 24))
          |> bxor(elem(@te1, uint8(s3 >>> 16)))
          |> bxor(elem(@te2, uint8(s0 >>> 8)))
          |> bxor(elem(@te3, uint8(s1)))
          |> bxor(get_deep(stks, [i, 2]))

        t3 =
          elem(@te0, uint8(s3 >>> 24))
          |> bxor(elem(@te1, uint8(s0 >>> 16)))
          |> bxor(elem(@te2, uint8(s1 >>> 8)))
          |> bxor(elem(@te3, uint8(s2)))
          |> bxor(get_deep(stks, [i, 3]))

        {t0, t1, t2, t3}
      end)

    tmp =
      <<s0::unsigned-big-size(32), s1::unsigned-big-size(32), s2::unsigned-big-size(32),
        s3::unsigned-big-size(32)>>

    ByteArray.write(ciphertext, 0, tmp)
  end

  defstruct [:derived_k]

  def new(key) when is_binary(key) do
    %__MODULE__{derived_k: stk_derive_k(ByteArray.new(key))}
  end

  defp blocksize_reduce(len, fun) do
    Enum.with_index(len..@block_size//-@block_size)
    |> Enum.reduce({len, 0}, fn {len, i}, {_len, _i} ->
      fun.(i)
      {len - @block_size, i + 1}
    end)
  end

  @doc """
  Encrypts a message using Deoxys-II authenticated encryption.

  ## Parameters

  - `self`: A DeoxysII struct containing the derived key.
  - `nonce`: A binary nonce (must be 15 bytes).
  - `ad`: Associated data that will be authenticated but not encrypted.
  - `msg`: The message to encrypt.

  ## Returns

  The encrypted message with the authentication tag appended.

  ## Example

  ```elixir
  # Create a new DeoxysII instance with a 32-byte key
  iex> key = Base.decode16!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", case: :lower)
  iex> nonce = Base.decode16!("000102030405060708090a0b0c0d0e0f", case: :lower)
  iex> ad = Base.decode16!("000102030405060708090a0b0c0d0e0f", case: :lower)
  iex> msg = Base.decode16!("000102030405060708090a0b0c0d0e0f", case: :lower)
  iex> x = DeoxysII.new(key)
  iex> ciphertext = DeoxysII.encrypt(x, nonce, ad, msg)
  iex> byte_size(ciphertext) == byte_size(msg) + DeoxysII.tag_size()
  true
  ```
  """
  def encrypt(%__MODULE__{} = self, nonce, ad, msg)
      when is_binary(nonce) and (is_binary(ad) or is_nil(ad)) and (is_binary(msg) or is_nil(msg)) do
    # Extracting to another process because of ByteArray state garbage
    isolate(fn -> do_encrypt(self, nonce, ad, msg) end)
  end

  defp do_encrypt(%__MODULE__{} = self, nonce, ad, msg)
       when is_binary(nonce) and (is_binary(ad) or is_nil(ad)) and (is_binary(msg) or is_nil(msg)) do
    tweak = ByteArray.new(@tweak_size)
    tmp = ByteArray.new(@block_size)
    dst = ByteArray.new(0)

    # Associated data.
    auth = ByteArray.new(@tag_size)

    if ad != nil do
      ad = ByteArray.new(ad)
      ad_len = ByteArray.len(ad)

      {ad_len, i} =
        blocksize_reduce(ad_len, fn i ->
          # 5. Auth <- Auth ^ Ek(0010||i, Ai+1)
          encode_tag_tweak(tweak, @prefix_ad_block, i)
          bc_encrypt(tmp, self.derived_k, tweak, ByteArray.sub(ad, i * 16, nil))
          xor_bytes(auth, auth, tmp, 16)
        end)

      if ad_len > 0 do
        # 8. Auth <- Auth ^ Ek(0110||la, pad10*(A*))
        encode_tag_tweak(tweak, @prefix_ad_final, i)
        a_star = ByteArray.new(16)
        tmp2 = ByteArray.sub(ad, ByteArray.len(ad) - ad_len, nil)

        for {a, b} <- ByteArray.enumerate(tmp2) do
          ByteArray.write(a_star, a, b)
        end

        ByteArray.write(a_star, ad_len, 0x80)
        bc_encrypt(tmp, self.derived_k, tweak, a_star)
        xor_bytes(auth, auth, tmp, 16)
      end
    end

    # Message authentication and tag generation.
    tag = ByteArray.clone(auth)

    if msg != nil do
      msg = ByteArray.new(msg)
      msg_len = ByteArray.len(msg)

      {msg_len, j} =
        blocksize_reduce(msg_len, fn j ->
          # 15. tag <- tag ^ Ek(0000||j, Mj+1)
          encode_tag_tweak(tweak, @prefix_msg_block, j)
          bc_encrypt(tmp, self.derived_k, tweak, ByteArray.sub(msg, j * @block_size, nil))
          xor_bytes(tag, tag, tmp, @block_size)
        end)

      if msg_len > 0 do
        # 18. tag <- tag & Ek(0100||l, pad10*(M*))
        encode_tag_tweak(tweak, @prefix_msg_final, j)

        m_star = ByteArray.new(@block_size)
        tmp2 = ByteArray.sub(msg, ByteArray.len(msg) - msg_len, nil)

        for {a, b} <- ByteArray.enumerate(tmp2) do
          ByteArray.write(m_star, a, b)
        end

        ByteArray.write(m_star, msg_len, 0x80)

        bc_encrypt(tmp, self.derived_k, tweak, m_star)
        xor_bytes(tag, tag, tmp, @block_size)
      end

      # 20. tag <- Ek(0001||0000||N, tag)
      enc_nonce = ByteArray.new(@block_size)
      ByteArray.write(enc_nonce, 1, binary_part(nonce, 0, @block_size - 1))
      ByteArray.write(enc_nonce, 0, @prefix_tag <<< @prefix_shift)
      bc_encrypt(tag, self.derived_k, enc_nonce, tag)

      # Message encryption.
      enc_blk = ByteArray.new(@block_size)
      # 0x00 || nonce
      ByteArray.write(enc_nonce, 0, 0)

      if msg != nil do
        msg_len = ByteArray.len(msg)

        {msg_len, j} =
          blocksize_reduce(msg_len, fn j ->
            # 24. Cj <- Mj ^ Ek(1||tag^j, 00000000||N)
            encode_enc_tweak(tweak, tag, j)
            bc_encrypt(enc_blk, self.derived_k, tweak, enc_nonce)

            for k <- 0..15 do
              ByteArray.write(
                dst,
                j * 16 + k,
                bxor(ByteArray.getb(msg, j * 16 + k), ByteArray.getb(enc_blk, k))
              )
            end
          end)

        if msg_len > 0 do
          # 24. C* <- M* ^ Ek(1||tag^l, 00000000||N)
          encode_enc_tweak(tweak, tag, j)
          bc_encrypt(enc_blk, self.derived_k, tweak, enc_nonce)

          for k <- 0..(msg_len - 1) do
            ByteArray.write(
              dst,
              j * 16 + k,
              bxor(ByteArray.getb(msg, j * 16 + k), ByteArray.getb(enc_blk, k))
            )
          end
        end
      end

      ByteArray.write(dst, ByteArray.len(dst), tag)
    end

    ByteArray.pop(dst)
  end

  @doc """
  Decrypts a ciphertext using Deoxys-II authenticated decryption.

  ## Parameters

  - `self`: A DeoxysII struct containing the derived key.
  - `nonce`: A binary nonce (must be 15 bytes).
  - `ad`: Associated data that will be authenticated.
  - `ciphertext`: The ciphertext to decrypt (with authentication tag appended).

  ## Returns

  The decrypted message if the authentication tag is valid, `nil` otherwise.

  ## Examples

  ```elixir
  iex> key = <<0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  ...>         0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f>>
  iex> nonce = <<0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e>>
  iex> deoxys = DeoxysII.new(key)
  iex> ciphertext = <<0x2b, 0x97, 0xbd, 0x77, 0x71, 0x2f, 0x0c, 0xde, 0x97, 0x53, 0x09, 0x95, 0x9d, 0xfe, 0x1d, 0x7c>>
  iex> DeoxysII.decrypt(deoxys, nonce, <<>>, ciphertext)
  <<>>

  # Encrypt and then decrypt a message with associated data
  iex> key = <<0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  ...>         0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f>>
  iex> nonce = <<0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e>>
  iex> ad = <<0x00, 0x01, 0x02>>
  iex> msg = <<0x10, 0x11, 0x12>>
  iex> deoxys = DeoxysII.new(key)
  iex> ct = DeoxysII.encrypt(deoxys, nonce, ad, msg)
  iex> DeoxysII.decrypt(deoxys, nonce, ad, ct)
  <<0x10, 0x11, 0x12>>
  ```
  """
  def decrypt(%__MODULE__{} = self, nonce, ad, ciphertext)
      when is_binary(nonce) and (is_binary(ad) or is_nil(ad)) and is_binary(ciphertext) do
    # Extracting to another process because of ByteArray state garbage
    isolate(fn -> do_decrypt(self, nonce, ad, ciphertext) end)
  end

  defp do_decrypt(%__MODULE__{} = self, nonce, ad, ciphertext)
       when is_binary(nonce) and (is_binary(ad) or is_nil(ad)) and is_binary(ciphertext) do
    dst = ByteArray.new(0)

    # Split out ct into ciphertext and tag.
    ciphertext = ByteArray.new(ciphertext)
    ct_len = ByteArray.len(ciphertext) - @tag_size
    tag = ByteArray.sub(ciphertext, ct_len, nil)
    ciphertext = ByteArray.sub(ciphertext, nil, ct_len)

    dec_tweak = ByteArray.new(@tweak_size)
    dec_blk = ByteArray.new(@block_size)
    dec_nonce = ByteArray.new(@block_size)
    # 0x00 || nonce
    ByteArray.write(dec_nonce, 1, nonce)

    {ct_len, j} =
      blocksize_reduce(ct_len, fn j ->
        # 4. Mj <- Cj ^ Ek(1||tag^j, 00000000||N)
        encode_enc_tweak(dec_tweak, tag, j)
        bc_encrypt(dec_blk, self.derived_k, dec_tweak, dec_nonce)

        for k <- 0..15 do
          ByteArray.write(
            dst,
            j * 16 + k,
            bxor(ByteArray.getb(ciphertext, j * 16 + k), ByteArray.getb(dec_blk, k))
          )
        end
      end)

    if ct_len > 0 do
      # 7. M* <- C* ^ Ek(1||tag^l, 00000000||N)
      encode_enc_tweak(dec_tweak, tag, j)
      bc_encrypt(dec_blk, self.derived_k, dec_tweak, dec_nonce)

      for k <- 0..(ct_len - 1) do
        ByteArray.write(
          dst,
          j * 16 + k,
          bxor(ByteArray.getb(ciphertext, j * 16 + k), ByteArray.getb(dec_blk, k))
        )
      end
    end

    # Associated data.
    auth = ByteArray.new(@tag_size)
    tweak = ByteArray.new(@tweak_size)
    tmp = ByteArray.new(@block_size)

    if ad != nil do
      ad = ByteArray.new(ad)
      ad_len = ByteArray.len(ad)

      {ad_len, i} =
        blocksize_reduce(ad_len, fn i ->
          # 14. Auth <- Auth ^ Ek(0010||i, Ai+1)
          encode_tag_tweak(tweak, @prefix_ad_block, i)
          bc_encrypt(tmp, self.derived_k, tweak, ByteArray.sub(ad, i * @block_size, nil))
          xor_bytes(auth, auth, tmp, @block_size)
        end)

      if ad_len > 0 do
        # 17. Auth <- Auth ^ Ek(0110||la, pad10*(A*))
        encode_tag_tweak(tweak, @prefix_ad_final, i)

        a_star = ByteArray.new(@block_size)
        tmp2 = ByteArray.sub(ad, ByteArray.len(ad) - ad_len, nil)

        for {a, b} <- ByteArray.enumerate(tmp2) do
          ByteArray.write(a_star, a, b)
        end

        ByteArray.write(a_star, ad_len, 0x80)

        bc_encrypt(tmp, self.derived_k, tweak, a_star)
        xor_bytes(auth, auth, tmp, @block_size)
      end
    end

    # Message authentication and tag generation.
    msg_len = ByteArray.len(dst)
    tag_p = ByteArray.clone(auth)

    {msg_len, j} =
      blocksize_reduce(msg_len, fn j ->
        # 24. tag' <- tag' ^ Ek(0000||j, Mj+1)
        encode_tag_tweak(tweak, @prefix_msg_block, j)
        bc_encrypt(tmp, self.derived_k, tweak, ByteArray.sub(dst, j * @block_size, nil))
        xor_bytes(tag_p, tag_p, tmp, @block_size)
      end)

    if msg_len > 0 do
      # 27. tag <- tag & Ek(0100||l, pad10*(M*))
      encode_tag_tweak(tweak, @prefix_msg_final, j)

      m_star = ByteArray.new(@block_size)
      tmp2 = ByteArray.sub(dst, ByteArray.len(dst) - msg_len, nil)

      for {a, b} <- ByteArray.enumerate(tmp2) do
        ByteArray.write(m_star, a, b)
      end

      ByteArray.write(m_star, msg_len, 0x80)

      bc_encrypt(tmp, self.derived_k, tweak, m_star)
      xor_bytes(tag_p, tag_p, tmp, @tag_size)
    end

    # 29. tag' <- Ek(0001||0000||N, tag')
    ByteArray.write(dec_nonce, 0, @prefix_tag <<< @prefix_shift)
    bc_encrypt(tag_p, self.derived_k, dec_nonce, tag_p)
    ret = ByteArray.pop(dst)

    # Tag verification
    if hmac_compare_digest(tag, tag_p) do
      ret
    end
  end

  defp hmac_compare_digest(a, b) do
    :crypto.hash_equals(ByteArray.pop(a), ByteArray.pop(b))
  end

  defp derive_sub_tweak_keys(derived_k, t) do
    stks =
      for _ <- 0..(@stk_count - 1) do
        [0, 0, 0, 0]
      end

    stk = ByteArray.new(@stk_size)

    write_stk = fn stks, idx, stk ->
      # Convert stk to a format that is easier to use with the
      # table driven AES round function.
      #
      # Note: Other implementations can just return each
      # Sub-Tweak Key as a 16 byte value.
      <<s0::unsigned-big-size(32), s1::unsigned-big-size(32), s2::unsigned-big-size(32),
        s3::unsigned-big-size(32)>> = ByteArray.sub(stk, nil, 16) |> ByteArray.pop()

      List.replace_at(stks, idx, [s0, s1, s2, s3])
    end

    # Tk1 = W1
    tk1 = ByteArray.sub(t, nil, @tweak_size)

    # i == 0
    xor_bytes(stk, Enum.at(derived_k, 0), tk1, @stk_size)
    stks = write_stk.(stks, 0, stk)

    # i == 1 ... i == 16
    Enum.reduce(1..@rounds, stks, fn i, stks ->
      # Tk1(i+1) = h(Tk1(i))
      stk_shuffle(tk1)
      xor_bytes(stk, Enum.at(derived_k, i), tk1, @stk_size)
      write_stk.(stks, i, stk)
    end)
  end

  defp isolate(fun) do
    ref = Process.alias()

    spawn_link(fn ->
      result = fun.()
      send(ref, {ref, result})
    end)

    receive do
      {^ref, result} -> result
    end
  end
end
