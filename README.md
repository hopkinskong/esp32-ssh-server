# ESP32 SSH Server

This is an example for ESP32 to act as a SSH server. The text typed to SSH will be transmitted to UART1, and vice versa.

WolfSSH and WolfSSL library is used to provide SSH and cryptographic functionalities.

## Issues

1. Codes need to have lots of cleanups, this repo, wolfssh-esp32, wolfssl-esp32 are just proof of concepts.
2. Currently only using ESP32 HW PRNG, encryption and decryption functions should be ported to use ESP32 APIs.
3. Auth is SHA256, not RSA.
4. Bugs when client is PuTTY, works fine in mysy32 ssh.
5. Running a long time >12h seems will hang the ESP32.


## Login Credentials

Username: hopkins

Password: hopkinsdev

## Warnings

Use at your own risk. This is just a proof of concept. Please generate a new public key instead of using the same key in this repository!

