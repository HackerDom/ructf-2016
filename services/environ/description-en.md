# Environ

## Introduction

Server was written on Python3.5 and consists of 2 parts:
+   simple web dashboard by Flask
+   server, which works by it own protocol over raw Wi-Fi

For identification teams in network, shared by all and nobody trust each other, server use RSA signing of its packets (each server publishes its public key by web); and for encryption server use honor Diffie-Hellman protocol of exchanging keys, only simplified by 64-bit modulus (p) and 32-bit checker private key (a), where service private key (b) was chosen from only 16 bits.

## Vulnerabilities

### DH

You can not crack this protocol in meaning time, if service private key was at least 32 bit, but it is 16. So, you can crack DH secret key for each "put" packet and get all flags of all commands at the moment they are been put.

There is working exploit for this: /ructf-2016/services/environ/tests/sploit.py, which remembers public part of DH exchange and crack it, when see new flag-packet.

### Guid?

When service write flag to disk, it uses function guid(), which use only 6 random hexdigits, so you can bruteforce them by /<some> and get all flags in service (you would not know, which are recent)

### Path traversal

Note, show_raw() not use send_static_file(), and use not recommended by Flask function send_file, which allows path traversal.
Sadly, service write its logs only to system-wide journald, so you can not simple read them, but you can access team RSA private key and use it to pretend them an grab their flags (but it is difficult, because if command doesn't get the flag - checksystem invalidate it, and you can not get flag points by it)
