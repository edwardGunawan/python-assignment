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
    return ''.join([encrypt(ch,3) for ch in plaintext])
    # raise NotImplementedError  # Your implementation here

def encrypt(character, letter):
    return chr((((ord(character)-ord('A')) + letter) % 26)+ord('A'))


def decrypt_caesar(ciphertext):
    """Decrypt a ciphertext using a Caesar cipher.
    It is the same as encrypt_ceasar, instead this time we minus 3 into the value

    (ord('alpha') - ord('A') - 3) % 26 + ord('A')

    """
    # raise NotImplementedError  # Your implementation here
    return ''.join([decrypt(ch,3) for ch in ciphertext])

def decrypt(character,letter):
    return chr((((ord(character)-ord('A')) - letter) % 26)+ord('A'))


# Vigenere Cipher

def encrypt_vigenere(plaintext, keyword):
    """Encrypt plaintext using a Vigenere cipher with a keyword.

    Add more implementation details here.

    Using decrypt helper function from above, pass in the keyword, as a number

    The keyword is repeated. Therefore, repeat the keyword by '+' each of them until the same length as the plain text

    slice the key word for the same length as the text
    """

    # raise NotImplementedError  # Your implementation here
    keyword_list = [ord(ch)-ord('A') for ch in keyword]
    while len(keyword_list) < len(plaintext):
        keyword_list += keyword_list


    keyword_list = keyword_list[:len(plaintext)] # slice keyword on the same length as plain text
    # print('keyword transformation', keyword_list)

    encrypted = ''.join(encrypt(c,int(l)) for c, l in zip(plaintext,keyword_list))
    # print('encrypted ', encrypted)
    return encrypted





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
    keyword_list = [ord(ct)-ord('A') for ct in keyword]

    print('keyword_list', keyword_list)

    while len(keyword_list) < len(ciphertext):
        keyword_list += keyword_list
    # slice into the same length as the ciphertext
    keyword_list = keyword_list[:len(ciphertext)]
    # print('keyword_list', keyword_list)

    decrypted = ''.join([decrypt(c,int(l)) for c, l in zip(ciphertext,keyword_list)]) # decrypt each keyword
    # print('decrypt letter', decrypted)
    return decrypted



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
    w_start = random.randint(2,10) # returns either 2 - 10 with uniform probability
    sum = w_start
    w = []
    for i in range(n):
        next_w = random.randint(sum+1, 2*sum)
        sum += next_w
        w.append(next_w)

    tuple_w = tuple(w) # converting w to tuple

    print ('super increasing sequence ', utils.is_superincreasing(tuple_w))

    # choose q
    q = random.randint(sum+1, 2*sum)

    # discover integer 'r' between 2 and q
    # loop through from 2 - q-1 and generate check if number is coprime of q if it is then break the loop
    r = 2
    for i in range (q-1):
        if utils.coprime(i,q):
            r = i
            break
    print('r is the number ', r)
    return (tuple_w,q,r)



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
                c_prime -= w_i*byte[i]

        result += chr(utils.bits_to_byte(byte[::-1]))

        return result
