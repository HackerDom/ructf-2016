#!/bin/bash
openssl genrsa -out squid.key
openssl req -new -key squid.key -out squid.csr
openssl x509 -req -days 3650 -in squid.csr -signkey squid.key -out squid.pem
