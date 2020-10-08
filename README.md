# Overview

This application consists from three parts. Server, man in the middle and client part.

By default server runs on 8081, man in the middle server runs on 8081 port.

Server reads AES key and initialization vector for file storage from `stdin`. 

# Usage

To run application firstly run server by running.

```
cat key.aes | python server.py
```

Then, you need to run man in the middle application using

```
python mim.py
```

After this, run client by

```
python client.py
```

Allowed commands for client are:

- get --- to read file
- edit --- to edit file
- delete --- to remove file
- new --- to create new file

To authenticate with test user use next credentials:

```
username: user
password: password
```
## Generating new key

To generate new key for server-side storage, run `generate_aes.sh` script. This script will generate 16 random bytes
for AES encryption and save them to file `key.aes`.

# Man in the middle

By default, client connects to man's in the middle server.
This server is a malefactor's server, which translates messages from client to server and prints
everything translated via protected channel, decrypting data.

Man in the middle breaks security by sending it's own RSA key for server on handshake step. Then it saves AES key in
memory and sends it to client, encrypting by client key. Now, MIM can read or even alter data translated between client
and server.
