def eea(a, b, x=0, y=1, xlast=1, ylast=0):
    if b == 0:
        return (a, xlast, ylast)
    q = a / b
    return eea(b, a % b, xlast - q * x, ylast - q * y, x, y)


def mod_inverse(a, m):
    gcd, x, y = eea(a, m)
    if gcd != 1:
        return None
    else:
        return (x % m + m) % m


def flatten(l):
    return [i for sl in l for i in sl]


def assert_values_are_coprime(a, m):
    assert mod_inverse(a, m), (
        "Multiplier ({}) is not coprime with max possible value."
        " Please supply correct multiplier.".format(a)
    )


class AffineDecryptor:
    def __init__(
        self,
        m,
        b,
        block_size,
        str_block_size,
        infile="ciphertext.txt",
        outfile="finalplaintextoutput.txt",
    ):
        self.m = m
        self.b = b
        self.block_size = block_size
        self.str_block_size = str_block_size
        self.infile = infile
        self.outfile = outfile
        self.max_input_val = self._get_max_value_for_block()
        assert_values_are_coprime(self.m, self.max_input_val)
        self.m_inverse = round(mod_inverse(self.m, self.max_input_val))
        self.msg = self._import_msg()
        self.decrypted_msg = None

    def _get_max_value_for_block(self):
        size = ""
        for _ in range(self.block_size):
            size = size + "25"
        return int(size) + 1

    def _strip_msg_padding(self, msg):
        return msg.rstrip("B")

    def _import_msg(self):
        with open(self.infile, "r") as f:
            return f.read()

    def write_decrypted(self):
        with open(self.outfile, "w") as f:
            f.write(self.decrypted_msg)

    def _numberify(self, msg_chars):
        return [ord(char) - 65 for char in msg_chars]

    def _charify(self, msg_ints):
        return [chr(int(i) + 65) for i in msg_ints]

    def _blockify(self, numeric_list):
        return [
            numeric_list[x : x + self.block_size]
            for x in range(0, len(numeric_list), self.block_size)
        ]

    def _break_block(self, block):
        return [
            int(letter)
            for letter in [
                block[i : i + self.str_block_size]
                for i in range(0, len(block), self.str_block_size)
            ]
        ]

    def _deblockify(self, blocked_list):
        return [self._break_block(block) for block in blocked_list]

    def _scrunch_block_to_int(self, block):
        return int("".join([str(val).zfill(self.str_block_size) for val in block]))

    def _decrypt_value(self, value):
        return (self.m_inverse * (value - self.b)) % self.max_input_val

    def _pad_out(self, value):
        return str(value).zfill(self.str_block_size * self.block_size)

    def _decrypt_blocks(self, blocks):
        return [
            self._pad_out(self._decrypt_value(self._scrunch_block_to_int(block)))
            for block in blocks
        ]

    def _destringify_encryption(self, encrypted_string):
        return self._blockify(self._numberify(list(encrypted_string)))

    def decrypt_msg(self):
        self.decrypted_msg = self._strip_msg_padding(
            "".join(
                self._charify(
                    flatten(
                        self._deblockify(
                            self._decrypt_blocks(self._destringify_encryption(self.msg))
                        )
                    )
                )
            )
        )


def main():
    try:
        m = int(input("Input multiplier for Block Affine cipher: "))
        b = int(input("Input offset for Block Affine cipher: "))
    except ValueError as ex:
        print(
            "Encountered error while parsing user input. Validate your input and try again."
        )
        raise
    cipher = AffineDecryptor(m, b, 3, 2)
    cipher.decrypt_msg()
    cipher.write_decrypted()


if __name__ == "__main__":
    main()
