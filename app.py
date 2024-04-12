from flask import Flask, render_template, request, redirect, url_for
import random 
import time


app = Flask(__name__)

@app.route('/encrypt/<text>')
def encryptText(text):
    try:
        # Function to generate prime numbers using Sieve of Eratosthenes
        def generate_primes(n):
            primes = [True] * (n + 1)
            primes[0], primes[1] = False, False
            p = 2
            while p ** 2 <= n:
                if primes[p]:
                    for i in range(p ** 2, n + 1, p):
                        primes[i] = False
                p += 1
            return [i for i in range(n + 1) if primes[i]]

        # Function to calculate the greatest common divisor using Euclid's algorithm
        def gcd(a, b):
            while b != 0:
                a, b = b, a % b
            return a

        # Function to calculate the modular inverse using extended Euclidean algorithm
        def mod_inverse(a, m):
            m0, x0, x1 = m, 0, 1
            while a > 1:
                q = a // m
                m, a = a % m, m
                x0, x1 = x1 - q * x0, x0
            return x1 + m0 if x1 < 0 else x1

        # Function to generate RSA key pair
        def generate_rsa_key_pair():
            # Generate three large prime numbers using Sieve of Eratosthenes
            primes = generate_primes(2**10)
            pn = random.choice(primes)
            qn = random.choice(primes)
            sn = random.choice(primes)

            # Calculate N
            N = pn * qn * sn

            # Calculate φ(N)
            phi_N = (pn - 1) * (qn - 1) * (sn - 1)

            # Choose e
            e = 65537  # Commonly used value for e
            while gcd(e, phi_N) != 1:
                e += 2

            # Calculate d
            d = mod_inverse(e, phi_N)

            # Calculate d_p, d_q, and q_inv
            d_p = d % (pn - 1)
            d_q = d % (qn - 1)
            q_inv = mod_inverse(qn, pn)

            # Public key
            public_key = (e, N)

            # Private key
            private_key = (q_inv, d_p, d_q, pn, qn)

            return public_key, private_key

        # Function for RSA encryption with bit stuffing
        def rsa_encrypt(plaintext, public_key):
            e, N = public_key
            ciphertext = [pow(ord(char), e, N) for char in plaintext]
            # Perform bit stuffing
            bit_stuffed_ciphertext = []
            for num in ciphertext:
                bit_string = bin(num)[2:]
                bit_stuffed = ''
                for bit in bit_string:
                    bit_stuffed += bit
                    if bit_stuffed[-3:] == '101' or bit_stuffed[-2:] == '01' or bit_stuffed[-1] == '1':
                        bit_stuffed += '0'  # Stuff a bit
                bit_stuffed_ciphertext.append(int(bit_stuffed, 2))
            return bit_stuffed_ciphertext

        # Function for RSA decryption with bit destuffing
        def rsa_decrypt(ciphertext, private_key):
            q_inv, d_p, d_q, pn, qn = private_key
            decrypted_ciphertext = []
            for num in ciphertext:
                bit_string = bin(num)[2:]
                bit_destuffed = ''
                i = 0
                while i < len(bit_string):
                    bit_destuffed += bit_string[i]
                    if bit_destuffed[-3:] == '101' or bit_destuffed[-2:] == '01' or bit_destuffed[-1] == '1':
                        i += 1  # Skip the stuffed bit
                    i += 1
                decrypted_ciphertext.append(int(bit_destuffed, 2))
            plaintext = ''.join([chr(pow(num, d_p, pn)) for num in decrypted_ciphertext])
            return plaintext

        # Example usage
        cond = True
        plaintext = text
        public_key, private_key = generate_rsa_key_pair()
        ciphertext = rsa_encrypt(plaintext, public_key)
        encryptedMessage = ""
        for i in range(len(ciphertext)):
            character = chr((ciphertext[i]% 26) + 97)
            encryptedMessage += character
        decrypted_plaintext = rsa_decrypt(ciphertext, private_key)

       
        if cond:
            return {'encrypted': encryptedMessage, 'decrypted': decrypted_plaintext}
        else:
            return {'error':"Please provide alphabets. Digits are not allowed"}
    
    except Exception as e:
        return {'error': "Please provide alphabets. Digits are not allowed"}

    
@app.route('/', methods=["GET", "POST"]) 
def hello_world():
    if request.method == 'POST': 
        message = request.form['message']
        result = encryptText(message)
        return render_template("index.html", result=result)
    else:
        return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
