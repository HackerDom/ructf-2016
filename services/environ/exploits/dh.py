# Third version of DH crack by bruteforce one of private keys
import sys

p = int(sys.argv[1])
g = int(sys.argv[2])
A = int(sys.argv[3])
B = int(sys.argv[4])
message = int(sys.argv[5])
a = 0
b = 0
secret = 1
s = 1

for i in range(p):
    s = (s * g) % p
    if s == A:
        secret = pow(B, i + 1, p)
        break
    if s == B:
        secret = pow(A, i + 1, p)
        break

print(int(message // secret).to_bytes(300, byteorder='big').strip(b'\0'))
