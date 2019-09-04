# Chainwallet-breaker
# https://www.reddit.com/r/Bitcoin/comments/cya467/chainwallet_challenge_get_01_btc_if_you_solve_it/
#
# Original code from Plutus Bitcoin Brute Forcer https://github.com/Isaacdelly/Plutus
#
# If this helps you -> bitcoin:bc1qamzgt95xwgtz504hcn6lvnam6yumnepqtrsmsa
 

import os
import hashlib
import binascii
import multiprocessing
import itertools
import string
from timeit import default_timer as timer
from ellipticcurve.privateKey import PrivateKey

length=6
max_power=5**6+1

def generate_all_possible_strings(length):
        """
        Returns an object with all possible lowercase char strings of chosen length
        """
        chars = string.ascii_lowercase  # "abcdefghijklmnopqrstuvwxyz"
        for item in itertools.product(chars, repeat=length):
                yield "".join(item)

def private_key_to_public_key(private_key):
	"""
	Accept a hex private key and convert it to its respective public key. 
	Because converting a private key to a public key requires SECP256k1 ECDSA 
	signing, this function is the most time consuming and is a bottleneck in 
	the overall speed of the program.
	Average Time: 0.0031567731 seconds
	"""
	pk = PrivateKey().fromString(bytes.fromhex(private_key))
	return '04' + pk.publicKey().toString().hex().upper()

def public_key_to_address(public_key):
	"""
	Accept a public key and convert it to its resepective P2PKH wallet address.
	Average Time: 0.0000801390 seconds
	"""
	output = []
	alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
	var = hashlib.new('ripemd160')
	encoding = binascii.unhexlify(public_key.encode())
	var.update(hashlib.sha256(encoding).digest())
	var_encoded = ('00' + var.hexdigest()).encode()
	digest = hashlib.sha256(binascii.unhexlify(var_encoded)).digest()
	var_hex = '00' + var.hexdigest() + hashlib.sha256(digest).hexdigest()[0:8]
	count = [char != '0' for char in var_hex].index(True) // 2
	n = int(var_hex, 16)
	while n > 0:
		n, remainder = divmod(n, 58)
		output.append(alphabet[remainder])
	for i in range(count): output.append(alphabet[0])
	return ''.join(output[::-1])

def private_key_to_WIF(private_key):
	"""
	Convert the hex private key into Wallet Import Format for easier wallet 
	importing. This function is only called if a wallet with a balance is 
	found. Because that event is rare, this function is not significant to the 
	main pipeline of the program and is not timed.
	"""
	digest = hashlib.sha256(binascii.unhexlify('80' + private_key)).hexdigest()
	var = hashlib.sha256(binascii.unhexlify(digest)).hexdigest()
	var = binascii.unhexlify('80' + private_key + var[0:8])
	alphabet = chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
	value = pad = 0
	result = ''
	for i, c in enumerate(var[::-1]): value += 256**i * c
	while value >= len(alphabet):
		div, mod = divmod(value, len(alphabet))
		result, value = chars[mod] + result, div
	result = chars[value] + result
	for c in var:
		if c == 0: pad += 1
		else: break
	return chars[0] * pad + result

def process_info():
    print('module name:', __name__)
    print('parent process:', os.getppid())
    print('process id:', os.getpid())

def main():
	"""
	Create the main pipeline by using an infinite loop to repeatedly call the 
	functions, while utilizing multiprocessing from __main__. Because all the 
	functions are relatively fast, it is better to combine them all into 
	one process.
	"""

####DEBUG password='aaaabc' and power 2^10 = 1024 rounds of sha256 -> address: 1GxVzZQMSH58D5Jf5M3tNBW7kczju8VHEW
##password='aaaaac'
##for x in range(0, 1024+1):
##        private_key = hashlib.sha256(password.encode('utf-8')).hexdigest()
##        password=private_key
##        if x==1024:
##                public_key = private_key_to_public_key(private_key) 	
##                address = public_key_to_address(public_key)
##                print('Address:',address)

process_info()
print('Generating ',max_power, 'rounds of sha256 for all ',length,' lowercase letter passwords')
print(max_power*26**length,' possibilities. This will take a while...')
	
for password in generate_all_possible_strings(length):
        print('Current password: ',password)
##      start = timer()                                                                 # Debug: Time between password cycles
        for x in range(0, max_power):
                private_key = hashlib.sha256(password.encode('utf-8')).hexdigest()      # One round of sha256(password)
                public_key = private_key_to_public_key(private_key)
                address = public_key_to_address(public_key)
                
                if address == '12FnVGpLqxmPTfENdyBso9HNbEdQEiHuhH':                     # Chainwallet wallet https://www.blockchain.com/btc/address/12FnVGpLqxmPTfENdyBso9HNbEdQEiHuhH
                        print('Power: ',x)
                        print('Password: ',password)
                        print('WIF: ', private_key_to_WIF(private_key))
                        print('Address: ',address)
                        exit(0)
                password=private_key
##        end = timer()
##        print(end - start)

if __name__ == '__main__':
        for cpu in range(multiprocessing.cpu_count()):
                multiprocessing.Process(target = main, args=()).start()
