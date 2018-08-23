#!/usr/bin/env python3 -tt
"""
File: crypto.py
---------------
Assignment 1: Cryptography
Course: CS 41
Name: <YOUR NAME>
SUNet: <SUNet ID>

Replace this with a description of the program.
"""
import utils
import random
import math

# Caesar Cipher

def encrypt_caesar(plaintext):
    """Encrypt plaintext using a Caesar cipher.

    Add more implementation details here.
    Ecrypting 3 letters after, by converting each letter into its ASCII character.
    Since Ascii character of ord('A') starts from 65, we set that as the base, by having
    'A' as 0 and 'Z' as 25.
    Therefore, if putting ord('Z') - ord('A'), as the base character
    encrypt_alpha = ((ord('alpha') - ord('A')) + 3) % 26 + ord('A') (total alphabet character)
    """
    result = ''

    for letter in plaintext:
        if letter.isalpha():
            letter = shift(letter,3)
            result += letter

    return result

def shift(character, shift):
    """ shift letter by shift letter in the alphabet

    This function takes a character string, which should be an upper case letter,
    and a shift value, which is an integer. It returns the letter shifted by
    the shift in the alphabet. The alphabet wraps around such that 'A' shifted -1
    is 'Z' and Z shifted +1 is 'A'
    """
    return chr((((ord(character)-ord('A')) + shift) % 26)+ord('A'))


def decrypt_caesar(ciphertext):
    """Decrypt a ciphertext using a Caesar cipher.
    It is the same as encrypt_ceasar, instead this time we minus 3 into the value

    (ord('alpha') - ord('A') - 3) % 26 + ord('A')

    """
    # raise NotImplementedError  # Your implementation here
    return ''.join([shift(ch,-3) for ch in ciphertext if ch.isalpha()])



# Vigenere Cipher

def encrypt_vigenere(plaintext, keyword):
    """Encrypt plaintext using a Vigenere cipher with a keyword.

    Add more implementation details here.

    Using shift helper function from above, pass in the keyword, as a number

    Getting the difference of hte length of plaintext and keyword. go through keyword and plaintext and shift each character

    The keyword is repeated. Therefore, repeat the keyword by '+' each of them until the same length as the plain text

    slice the key word for the same length as the text
    """
    result = ''

    diff = math.ceil(len(plaintext)/len(keyword))

    for letter,key in zip(plaintext,keyword*diff):
        result += shift(letter,ord(key)-ord('A')) # indicating how many shift we need

    return result



def decrypt_vigenere(ciphertext, keyword):
    """Decrypt ciphertext using a Vigenere cipher with a keyword.

    Add more implementation details here.
    Using decreypt helper function from above to decrypt to the previous character
    Converting keyword:
       1. Change keyword to charater of list
       2. Adding its length into list until it is bigger or equal to ciphertext
       3. Slice key word to make create the same length as the ciphertext
    Loop through ciphertext, using comprehension list and create a decryption on each ciphertext
    """
    result = ''
    diff = math.ceil(len(ciphertext)/len(keyword))

    for letter,key in zip(ciphertext,keyword*diff):
        result += shift(letter,ord('A')-ord(key)) # indicating left shift

    return result



# Merkle-Hellman Knapsack Cryptosystem
def generate_private_key(n=8):
    """Generate a private key for use in the Merkle-Hellman Knapsack Cryptosystem.

    Following the instructions in the handout, construct the private key components
    of the MH Cryptosystem. This consistutes 3 tasks:

    1. Build a superincreasing sequence `w` of length n
        (Note: you can check if a sequence is superincreasing with `utils.is_superincreasing(seq)`)
    2. Choose some integer `q` greater than the sum of all elements in `w`
    3. Discover an integer `r` between 2 and q that is coprime to `q` (you can use utils.coprime)

    You'll need to use the random module for this function, which has been imported already

    Somehow, you'll have to return all of these values out of this function! Can we do that in Python?!

    @param n bitsize of message to send (default 8)
    @type n int

    @return 3-tuple `(w, q, r)`, with `w` a n-tuple, and q and r ints.
    """
    w = tuple(get_super_incr_series(n,2,10))
    q = get_next_incr_series(w)
    r = get_coprime(q)
    return w, q, r

def get_super_incr_series(n,i_start,i_end):
    """ Construct a list containing a superincreasing series. List is of length
    n. The first start number is a random number between i_start, and i_end
    inclusive
    """
    start = random.randint(i_start,i_end)
    incr_series = [start]

    while len(incr_series) < n:
        incr_series.append(get_next_incr_series(incr_series))

    return incr_series


def get_next_incr_series(nums):
    """ Takes a super increasing series and returns an integer that is larger
    than the sum of the super increasing series, i.e. a value that could come next
    in the series. The return value is a number between the sum of the series + 1
    and the sum of the series*2
    """
    total = sum(nums)
    return random.randint(total+1, total*2)


def get_coprime(q):
    """ returns a random coprime of q that is less than q.
    """
    r = random.randint(2,q-1)
    while not utils.coprime(q,r):
        r = random.randint(2,q-1)

    return r





def create_public_key(private_key):
    """Create a public key corresponding to the given private key.

    To accomplish this, you only need to build and return `beta` as described in the handout.

        beta = (b_1, b_2, ..., b_n) where b_i = r × w_i mod q

    Hint: this can be written in one line using a list comprehension

    @param private_key The private key
    @type private_key 3-tuple `(w, q, r)`, with `w` a n-tuple, and q and r ints.

    @return n-tuple public key
    """
    w , q, r = private_key
    return tuple([(r*w_i) %q for w_i in w])


def encrypt_mh(message, public_key):
    """Encrypt an outgoing message using a public key.

    1. Separate the message into chunks the size of the public key (in our case, fixed at 8)
    2. For each byte, determine the 8 bits (the `a_i`s) using `utils.byte_to_bits`
    3. Encrypt the 8 message bits by computing
         c = sum of a_i * b_i for i = 1 to n
    4. Return a list of the encrypted ciphertexts for each chunk in the message

    Hint: think about using `zip` at some point

    @param message The message to be encrypted
    @type message bytes
    @param public_key The public key of the desired recipient
    @type public_key n-tuple of ints

    @return list of ints representing encrypted bytes
    """

    ciphers = []

    for letter in message:
        bits_arr = utils.byte_to_bits(letter)
        ciphers.append(
            sum([bit*public_key[i] for i,bit in enumerate(bits_arr)])
        )

    return ciphers



def decrypt_mh(message, private_key):
    """Decrypt an incoming message using a private key

    1. Extract w, q, and r from the private key
    2. Compute s, the modular inverse of r mod q, using the
        Extended Euclidean algorithm (implemented at `utils.modinv(r, q)`)
    3. For each byte-sized chunk, compute
         c' = cs (mod q)
    4. Solve the superincreasing subset sum using c' and w to recover the original byte
    5. Reconsitite the encrypted bytes to get the original message back

    @param message Encrypted message chunks
    @type message list of ints
    @param private_key The private key of the recipient
    @type private_key 3-tuple of w, q, and r

    @return bytearray or str of decrypted characters
    """
    w,q,r = private_key

    s = utils.modinv(r,q)

    result = ''

    for chunk in message:
        c_prime = chunk * s % q

        w_rev = w[::-1]
        byte = [0]*len(w)

        # This problem is computationally easy because w was chosen to be a
        # superincreasing sequence! Take the largest element in w, say w_k.
        # If w_k > c' , then a_k = 0, and if w_k <= c', then a_k = 1. Then,
        # subtract w_k × a_k from c' , and repeat these steps until you have figured
        # out all of alpha.
        for i, w_i in enumerate(w_rev):
            if w_i <= c_prime:
                byte[i]=1
                c_prime -= w_i

        result += chr(utils.bits_to_byte(byte[::-1]))

        return result
