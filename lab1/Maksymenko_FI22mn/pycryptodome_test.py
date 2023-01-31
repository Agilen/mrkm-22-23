import Crypto.Random
import time
from Crypto.Cipher import AES
from Crypto.Hash import SHA512, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


def test_aes(seconds=3, block_size=2048):
    print(f"______________________________AES-CBC-256 testing for {seconds} seconds.______________________________")

    key = b'doesnt matter very much only len'
    cipher = AES.new(key, AES.MODE_CBC)
    pt = Crypto.Random.get_random_bytes(block_size)

    t_end = time.time() + seconds

    iterations = 0
    while time.time() < t_end:
        ct = cipher.encrypt(pt)
        iterations += 1

    print(f"{iterations = }, {block_size = } bytes")
    print(f"totaling to {iterations * block_size / 1000 / 1000 / seconds} MB/s ")


def test_sha256(seconds=3, block_size=2048):
    print(f"______________________________SHA-256 testing for {seconds} seconds.______________________________")
    data = Crypto.Random.get_random_bytes(block_size)

    t_end = time.time() + seconds
    iterations = 0
    while time.time() < t_end:
        hasher = SHA256.new(data=data)
        hashed = hasher.digest()
        iterations += 1

    print(f"{iterations = }, {block_size = } bytes")
    print(f"totaling to {iterations * block_size / 1000 / 1000 / seconds} MB/s ")

def test_sha512(seconds=3, block_size=2048):
    print(f"______________________________SHA-512 testing for {seconds} seconds.______________________________")
    data = Crypto.Random.get_random_bytes(block_size)

    t_end = time.time() + seconds
    iterations = 0
    while time.time() < t_end:
        hasher = SHA512.new(data=data)
        hashed = hasher.digest()
        iterations += 1

    print(f"{iterations = }, {block_size = } bytes")
    print(f"totaling to {iterations * block_size / 1000 / 1000 / seconds} MB/s ")



def test_rsa_sign(seconds=10, block_size=2048):
    print(
        f"______________________________RSA {block_size} sign testing for {seconds} seconds.______________________________")

    key = RSA.generate(block_size)
    message = Crypto.Random.get_random_bytes(block_size // 8)
    h = SHA256.new(message)

    t_end = time.time() + seconds
    iterations = 0
    signer = pkcs1_15.new(key)
    while time.time() < t_end:
        signature = signer.sign(h)
        iterations += 1

    print(f"{iterations = }, {block_size = } bits")
    print(f"totaling to {iterations / seconds} signs/s ")
    print(f"{seconds / iterations} seconds / sign ")
    print(f"{seconds / iterations * 1000} milliseconds / sign ")


def test_rsa_verify(seconds=10, block_size=2048):
    print(
        f"______________________________RSA {block_size} verify testing for {seconds} seconds.______________________________")

    key = RSA.generate(block_size)
    message = Crypto.Random.get_random_bytes(block_size // 8)
    h = SHA256.new(message)

    signature = pkcs1_15.new(key).sign(h)

    verifier = pkcs1_15.new(key)
    t_end = time.time() + seconds
    iterations = 0
    while time.time() < t_end:
        verifier.verify(h, signature)
        iterations += 1

    print(f"{iterations = }, {block_size = } bits")
    print(f"totaling to {iterations / seconds} verifications/s ")
    print(f"{seconds / iterations} seconds / verification ")
    print(f"{seconds / iterations * 1000} milliseconds / verification ")


if __name__ == "__main__":
    for test in [test_aes, test_sha256,test_sha512]:
        for block_size in [16, 64, 256, 1024, 8192, 16384]:
            test(block_size=block_size)
    for test in [test_rsa_sign, test_rsa_verify]:
        for block_size in [1024, 2048, 4096]:
            test(block_size=block_size)
