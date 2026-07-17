# nwire control protocol v1

`POST /v1/auth` carries an `AuthRequest` JSON object. Its signature is made
over `nwire-auth-v1\0` followed by each field as a 4-byte big-endian length and
UTF-8 bytes: public key, WireGuard public key, timestamp, nonce, OS, arch,
hostname, username, client version, then sorted extra-map key/value pairs.
The server accepts timestamps within two minutes and rejects previously seen
nonces. `GET /v1/info` advertises the protocol version; `POST /v1/disconnect`
requires `Authorization: Bearer <token>`.

The response's tunnel list is an authorization grant, never a request to dial
an arbitrary target. WireGuard transport and WebSocket encapsulation are
reserved for the next transport milestone; this repository does not claim
interoperability for either until they are implemented.
