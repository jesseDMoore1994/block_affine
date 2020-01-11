import sys
import re


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
        "Multiplier ({}) and max possible value ({}) are not coprime."
        " Please supply another multiplier.".format(a, m)
    )


class AffineEncryptor:
    def __init__(
        self,
        m,
        b,
        block_size,
        str_block_size,
        infile="plaintext.txt",
        outfile="ciphertext.txt",
    ):
        self.m = m
        self.b = b
        self.block_size = block_size
        self.str_block_size = str_block_size
        self.infile = infile
        self.outfile = outfile
        self.max_input_val = self._get_max_value_for_block()
        assert_values_are_coprime(self.m, self.max_input_val)
        self.msg = self._import_msg()
        self.encrypted_msg = None

    def _get_max_value_for_block(self):
        size = ""
        for _ in range(self.block_size):
            size = size + "25"
        return int(size) + 1

    def _pad_msg(self, msg):
        if len(msg) % self.block_size != 0:
            for _ in range(self.block_size - (len(msg) % self.block_size)):
                msg = msg + "B"
        return msg

    def _import_msg(self):
        with open(self.infile, "r") as f:
            return self._pad_msg(re.sub("[^A-Z]", "", f.read()))

    def write_encrypted(self):
        with open(self.outfile, "w") as f:
            f.write(self.encrypted_msg)

    def _numberify(self, msg_chars):
        return [ord(char) - 65 for char in msg_chars]

    def _charify(self, msg_ints):
        return [chr(int(i) + 65) for i in msg_ints]

    def _blockify(self, numeric_list):
        return [
            numeric_list[x : x + self.block_size]
            for x in range(0, len(numeric_list), self.block_size)
        ]

    def _scrunch_block_to_int(self, block):
        return int("".join([str(val).zfill(self.str_block_size) for val in block]))

    def _encrypt_value(self, value):
        return ((self.m * value) + self.b) % self.max_input_val

    def _encrypt_blocks(self, blocks):
        return [
            self._encrypt_value(value)
            for value in [self._scrunch_block_to_int(block) for block in blocks]
        ]

    def _stringify_encrypted_block(self, block):
        return [
            block[i : i + self.str_block_size]
            for i in range(0, len(block), self.str_block_size)
        ]

    def _stringify_encryption(self, encrypted_blocks):
        return "".join(
            self._charify(
                flatten(
                    [
                        self._stringify_encrypted_block(block)
                        for block in [
                            str(val).zfill(self.str_block_size * self.block_size)
                            for val in encrypted_blocks
                        ]
                    ]
                )
            )
        )

    def encrypt_msg(self):
        self.encrypted_msg = self._stringify_encryption(
            self._encrypt_blocks(self._blockify(self._numberify(list(self.msg))))
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
    cipher = AffineEncryptor(m, b, 3, 2)
    cipher.encrypt_msg()
    cipher.write_encrypted()


if __name__ == "__main__":
    main()
