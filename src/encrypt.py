import re


# encrypt.py
# Program authored by Jesse Moore for CS 585
# 1/27/20
# This file takes a text file and encrypts it using
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
        "Multiplier ({}) and max possible value ({}) are not coprime."
        " Please supply another multiplier.".format(a, m)
    )


# This class holds all of the encryption logic.
class AffineEncryptor:
    # Initializer function
    def __init__(
        self,
        m,
        b,
        block_size,
        str_block_size,
        infile="plaintext.txt",
        outfile="ciphertext.txt",
    ):
        # store important data.
        self.m = m
        self.b = b
        self.block_size = block_size
        self.str_block_size = str_block_size
        self.infile = infile
        self.outfile = outfile

        # calculate max block size.
        self.max_input_val = self._get_max_value_for_block()

        # assert user multiplier can be used.
        assert_values_are_coprime(self.m, self.max_input_val)

        # pull in message from file.
        self.msg = self._import_msg()

        # define variable to store encrypted text.
        self.encrypted_msg = None

    # this function calculates the max block value possible.
    def _get_max_value_for_block(self):
        size = ""
        # block_size = 1, max val is 26
        # block_size = 2, max val is 2526
        # etc.
        for _ in range(self.block_size):
            size = size + "25"
        return int(size) + 1

    # pad the message with "B" to make if flush with block size.
    def _pad_msg(self, msg):
        # if the length of the message is not flush with block size
        if len(msg) % self.block_size != 0:
            # add a "B" until flush.
            for _ in range(self.block_size - (len(msg) % self.block_size)):
                msg = msg + "B"
        return msg

    # import the plaintext message and sanitize if needed.
    def _import_msg(self):
        # open text file.
        with open(self.infile, "r") as f:
            data = f.read()
            # if there are illegal characters, produce a warning.
            if re.search("[^A-Z]", data):
                print("Warning! Illegal characters detected, cleaning and proceeding.")
            # strip illegal characters if needed and pad the message.
            return self._pad_msg(re.sub("[^A-Z]", "", data))

    # write the encrypted message out to the output file.
    def write_encrypted(self):
        with open(self.outfile, "w") as f:
            f.write(self.encrypted_msg)

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

    # take a block of integer represented charcters and squish it to one integer value.
    # I.E. [25, 25, 25] => 252525
    def _scrunch_block_to_int(self, block):
        return int("".join([str(val).zfill(self.str_block_size) for val in block]))

    # encrypt a block value using affine encryption method.
    def _encrypt_value(self, value):
        return ((self.m * value) + self.b) % self.max_input_val

    # encrypt a list of blocks one by one using affine encryption.
    def _encrypt_blocks(self, blocks):
        return [
            self._encrypt_value(value)
            for value in [self._scrunch_block_to_int(block) for block in blocks]
        ]

    # break a block back into its individual characters.
    def _deblockify(self, block):
        return [
            block[i : i + self.str_block_size]
            for i in range(0, len(block), self.str_block_size)
        ]

    # create a string from encrypted blocks
    def _stringify_encryption(self, encrypted_blocks):
        # it helps to read this function from the inside out
        # we create a list of blocks, deblockify each, flatten
        # them into a flat list, convert them to a character
        # representation, and then join them into a string.
        return "".join(
            self._charify(
                flatten(
                    [
                        self._deblockify(block)
                        for block in [
                            str(val).zfill(self.str_block_size * self.block_size)
                            for val in encrypted_blocks
                        ]
                    ]
                )
            )
        )

    # encrypt the message stored in the text file given by the user.
    def encrypt_msg(self):
        # create the encrypted message by converting the message to a list,
        # converting it to a integer representation, make those ints into blocks,
        # encrypt those blocks, then string them together.
        self.encrypted_msg = self._stringify_encryption(
            self._encrypt_blocks(self._blockify(self._numberify(list(self.msg))))
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

    # create an Affine Encryptor, encrypt the message, and write it out.
    cipher = AffineEncryptor(m, b, 3, 2)
    cipher.encrypt_msg()
    cipher.write_encrypted()


# call main function if this file is called directly.
if __name__ == "__main__":
    main()
