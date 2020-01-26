# decrypt.py
# Program authored by Jesse Moore for CS 585
# 1/27/20
# This file takes a text file and decrypts it using
# the block affine cipher method.

# This is a recursive function used to calculate
# a, xlast, and ylast using the extended euclidean
# algorithm.
def eea(a, b, x=0, y=1, xlast=1, ylast=0):
    # base case.
    if b == 0:
        return (a, xlast, ylast)

    # calculate new quotient.
    q = a / b

    # call recursivly with new parameters.
    return eea(b, a % b, xlast - q * x, ylast - q * y, x, y)


# This function is used to determine a modular
# inverse if it exists. returns None otherwise.
def mod_inverse(a, m):
    # calculate gcd and x using extended euclidian algorithm.
    gcd, x, y = eea(a, m)

    # check for coprimeness.
    if gcd != 1:
        # if not coprimes, exit.
        return None
    else:
        # if coprimes, return a modular inverse.
        return (x % m + m) % m


# This function flattens a list of lists into
# a single list.
def flatten(l):
    return [i for sl in l for i in sl]


# This function asserts that the given multipler is coprime
# to the max block size by asserting a modular inverse exists.
def assert_values_are_coprime(a, m):
    assert mod_inverse(a, m), (
        "Multiplier ({}) is not coprime with max possible value."
        " Please supply correct multiplier.".format(a)
    )


# This class holds all of the encryption logic.
class AffineDecryptor:
    # initializer function
    def __init__(
        self,
        m,
        b,
        block_size,
        str_block_size,
        infile="ciphertext.txt",
        outfile="finalplaintextoutput.txt",
    ):
        # store important data
        self.m = m
        self.b = b
        self.block_size = block_size
        self.str_block_size = str_block_size
        self.infile = infile
        self.outfile = outfile

        # calculate max block value.
        self.max_input_val = self._get_max_value_for_block()

        # assert user multiplier can be used
        assert_values_are_coprime(self.m, self.max_input_val)

        # get modular inverse for decryption
        self.m_inverse = round(mod_inverse(self.m, self.max_input_val))

        # pull in message from file
        self.msg = self._import_msg()

        # define variable used to store decrpyted text
        self.decrypted_msg = None

    # this function calculates the max block value possible.
    def _get_max_value_for_block(self):
        size = ""
        # block_size = 1, max val is 26
        # block_size = 2, max val is 2526
        # etc.
        for _ in range(self.block_size):
            size = size + "25"
        return int(size) + 1

    # remove extra "B"s from end of message
    def _strip_msg_padding(self, msg):
        return msg.rstrip("B")

    # import encrpyted message from input file
    def _import_msg(self):
        with open(self.infile, "r") as f:
            return f.read()

    # write decrypted message to output file
    def write_decrypted(self):
        with open(self.outfile, "w") as f:
            f.write(self.decrypted_msg)

    # convert characters into their integer representation.
    def _numberify(self, msg_chars):
        return [ord(char) - 65 for char in msg_chars]

    # convert integers into their character representation.
    def _charify(self, msg_ints):
        return [chr(int(i) + 65) for i in msg_ints]

    # turn a list of numbers into a list of blocks.
    def _blockify(self, numeric_list):
        return [
            numeric_list[x : x + self.block_size]
            for x in range(0, len(numeric_list), self.block_size)
        ]

    # break a block into a list of integer components
    def _break_block(self, block):
        return [
            int(letter)
            for letter in [
                block[i : i + self.str_block_size]
                for i in range(0, len(block), self.str_block_size)
            ]
        ]

    # convert a list of blocks into a list of lists containing integer components
    def _deblockify(self, blocked_list):
        return [self._break_block(block) for block in blocked_list]

    # convert a block into its integer representation
    def _scrunch_block_to_int(self, block):
        return int("".join([str(val).zfill(self.str_block_size) for val in block]))

    # decrypt a block value using affine decryption
    def _decrypt_value(self, value):
        return (self.m_inverse * (value - self.b)) % self.max_input_val

    # pad out a value to match the block size
    def _pad_out(self, value):
        return str(value).zfill(self.str_block_size * self.block_size)

    # decrypt a list of blocks
    def _decrypt_blocks(self, blocks):
        # for each block, squish it to its integer representation, decrypt it,
        # and then pad it block size
        return [
            self._pad_out(self._decrypt_value(self._scrunch_block_to_int(block)))
            for block in blocks
        ]

    # turn an encrypted string into blocks
    def _destringify_encryption(self, encrypted_string):
        # convert the encryted string to a list, turn it into integer representation
        # and turn it into blocks
        return self._blockify(self._numberify(list(encrypted_string)))

    # decrypt the message from the input file
    def decrypt_msg(self):
        # it helps to read this section inside out
        # destringify the message into blocks, decrypt those blocks,
        # convert them out of block format, flatten them into a list,
        # convert them to characters, and string them together.
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
        # get user input
        m = int(input("Input multiplier for Block Affine cipher: "))
        b = int(input("Input offset for Block Affine cipher: "))
    except ValueError as ex:
        # catch any bad input and error out
        print(
            "Encountered error while parsing user input. Validate your input and try again."
        )
        raise

    # create an Affine Decryptor, decrypt the message, and write it out
    cipher = AffineDecryptor(m, b, 3, 2)
    cipher.decrypt_msg()
    cipher.write_decrypted()


# call main function if this file is called directly.
if __name__ == "__main__":
    main()
