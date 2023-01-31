import Crypto.Random
from Crypto.PublicKey import RSA, DSA, ECC, ElGamal

print("\n-------------RSA-------------\n")
RSA_key = RSA.generate(1024)
print(RSA_key.export_key())
print(RSA_key.public_key().export_key())

print("\n-------------DSA-------------\n")
DSA_key = DSA.generate(1024)
print(DSA_key.export_key())
print(DSA_key.public_key().export_key())

print("\n-------------ECC-------------\n")
ECC_key = ECC.generate(curve='P-256')
print(ECC_key.export_key(format='PEM'))
print(ECC_key.public_key().export_key(format='PEM'))

print("\n-------------ElGamal-------------\n")
ElGamal_key = ElGamal.generate(512, Crypto.Random.get_random_bytes)
print(f"Public key:\n{ElGamal_key.g = }\n{ElGamal_key.p = }\n{ElGamal_key.y = }\n")
print(f"Private key:\n{ElGamal_key.x = }\n")

