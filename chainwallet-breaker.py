# Chainwallet-breaker
# https://www.reddit.com/r/Bitcoin/comments/cya467/chainwallet_challenge_get_01_btc_if_you_solve_it/
# Original Bitcoin functions from from Plutus Bitcoin Brute Forcer: https://github.com/Isaacdelly/Plutus
#
# If this helps you -> bitcoin:bc1qamzgt95xwgtz504hcn6lvnam6yumnepqtrsmsa
 

import os
import binascii
import itertools
import string
import hashlib
import random
import sys
from timeit import default_timer as timer
from ellipticcurve.privateKey import PrivateKey

PASSWORD_LENGTH=6
DEFAULT_PASSWORD=''                     # The program will use DEFAULT_PASSWORD, if set, to start brute-forcing, then continue with the rest of possible passwords
MIN_POWER=2                             # Min base and exp to be checked :     2^2
MAX_POWER=10                            # Max base and exp to be checked -1 :  9^9


VALID_MODES = {'r','e', 'R','E'}                           #Modes: Random, Exhaustive

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
    print('Running:', __name__)
    print('parent process:', os.getppid())
    print('process id:', os.getpid())
    
def sha256_ntimes(password, times):
    for i in range(times):
        private_key = hashlib.sha256(password.encode('utf-8')).hexdigest()
        password=private_key
    return private_key

def generate_random(size=PASSWORD_LENGTH, chars=string.ascii_lowercase):
        return ''.join(random.choice(chars) for _ in range(size))                                       # Source: https://stackoverflow.com/questions/2257441/random-string-generation-with-upper-case-letters-and-digits/23728630#23728630

if __name__ == '__main__':

        mode = input("Select a mode - Random (r/R) or Exhaustive (e/E): ")
        if mode not in VALID_MODES:
                exit(-1)
      
        used_words=[]
        password=''
        process_info()

        if mode=='r' or mode=='R':                                                                              # RANDOM MODE: Will test random 6 letter passwords


                # Ask user if they are feeling lucky for a DEFAULT_PASSWORD
                DEFAULT_PASSWORD = input("Insert a first password to be tested (if you feel lucky): ")
                
                while True:
                        print('Running in random mode')
                        all_exps = (i**exp for exp in range(MIN_POWER,MAX_POWER) for i in range(MIN_POWER,MAX_POWER))
                        timer_count=0                                                                           # timer set to zero


                        if DEFAULT_PASSWORD=='' or password in used_words:
                                password=generate_random()
                        else:         
                                password=DEFAULT_PASSWORD.lower()
                                print('Using input password: ',password) 

                        used_words.append(password)
                        print('Current password: ',password)  
                        for current in all_exps:
                                        start = timer()
                                        print('SHA256 times: ',current)
                                        private_key = sha256_ntimes(password,current)
                                        public_key = private_key_to_public_key(private_key)
                                        address = public_key_to_address(public_key)
                                        end = timer()

                                        ### DEBUG: Simple password to test it works ###
                                        ### password 'aaaaac'
                                        ### address == 1DFe1d61VPqCDZfJ35rnRRUhuqSDg5s59z
                                        
                                        if address == '12FnVGpLqxmPTfENdyBso9HNbEdQEiHuhH':                     # Chainwallet wallet https://www.blockchain.com/btc/address/12FnVGpLqxmPTfENdyBso9HNbEdQEiHuhH
                                                        with open('results.txt', 'a') as file:                  # IF FOUND write to file!!!
                                                                        file.write('power: ' + str(current) + '\n' +
                                                                                           'password:' + str(password) + '\n' +
                                                                                           'WIF private key: ' + str(private_key_to_WIF(private_key)) + '\n' +
                                                                                           'address: ' + str(address) + '\n\n')
                                                        exit(0)
                                        timer_count+= (end-start)
                        print('Total time: %.2f.' %timer_count)

        else:                                                                                                   # EXHAUSTIVE MODE: Will test all 6 letter words from aaaaaa to zzzzz
                for password in generate_all_possible_strings(PASSWORD_LENGTH):
                        print('Running in random mode')
                        all_exps = (i**exp for exp in range(MIN_POWER,MAX_POWER) for i in range(MIN_POWER,MAX_POWER))
                        timer_count=0                                                                           # timer set to zero

                        used_words.append(password)
                        print('Current password: ',password)  
                        for current in all_exps:
                                        start = timer()
                                        print('SHA256 times: ',current)
                                        private_key = sha256_ntimes(password,current)
                                        public_key = private_key_to_public_key(private_key)
                                        address = public_key_to_address(public_key)
                                        end = timer()

                                        ### DEBUG: Simple password to test it works ###
                                        ### password 'aaaaac'
                                        ### address == 1DFe1d61VPqCDZfJ35rnRRUhuqSDg5s59z
                                        
                                        if address == '12FnVGpLqxmPTfENdyBso9HNbEdQEiHuhH':                     # Chainwallet wallet https://www.blockchain.com/btc/address/12FnVGpLqxmPTfENdyBso9HNbEdQEiHuhH
                                                        with open('results.txt', 'a') as file:                  # IF FOUND write to file!!!
                                                                        file.write('power: ' + str(current) + '\n' +
                                                                                           'password:' + str(password) + '\n' +
                                                                                           'WIF private key: ' + str(private_key_to_WIF(private_key)) + '\n' +
                                                                                           'address: ' + str(address) + '\n\n')
                                                        exit(0)
                                        timer_count+= (end-start)
                        print('Total time: %.2f.' %timer_count)
                                        
                        ### DEBUG: Uncomment to see words used while running ###
                        print('Words used: ',*used_words,'\n')

                        
