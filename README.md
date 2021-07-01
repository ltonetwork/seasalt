![github-banner](https://user-images.githubusercontent.com/100821/122219870-25e0fd80-ceb0-11eb-8e51-906bbbb27c92.png)

# SeaSalt

[NaCl](https://nacl.cr.yp.to/) and [libsodium](https://libsodium.gitbook.io/doc/) compatible library for public-key
cryptography and hashing using [Bouncy Castle](https://www.bouncycastle.org/).
\
\
_Secret key cryptography is **not** supported. PRs to add secret key cryptography to this library will be accepted._

## Public key signature algoritms

- Ed25519
- ECDSA
  - secp256r1 (aka NIST P-256)
  - secp256k1
  - More curves listed [here](https://people.eecs.berkeley.edu/~jonah/javadoc/org/bouncycastle/asn1/sec/SECNamedCurves.html)

## Hashing algorithms

- SHA1
- SHA2 (SHA-256, SHA-384, SHA-512)
- SHA3 (SHA3-256, SHA3-384, SHA3-512)
- Blake2b (Blake2b-256, Blake2b-384, Blake2b-512)
- Keccak (Keccak-256, Keccak-384, Keccak-512)

# Usage

## Public key signatures

`KeyPair keyPair()`\
Create a random KeyPair.

`KeyPair keyPairFromSeed(byte[] seed)`\
Create a KeyPair from seed.

`KeyPair keyPairFromSecretKey(byte[] privateKey)`\
Create a KeyPair from a private key.

`Binary signDetached(byte[]|Binary|String msg, byte[]|Binary|KeyPair privateKey)`\
Sign a message using a private key or a KeyPair. The return value is the digital signature of type Binary.

`boolean verify(byte[]|Binary|String msg, byte[]|Binary|KeyPair signature, byte[]|Binary publicKey)`\
Verify a signature using a public key or a KeyPair.

_A `sign` method which prepends the message to the signature, compatible with
[libsodium's combined mode](https://libsodium.gitbook.io/doc/public-key_cryptography/public-key_signatures#combined-mode),
is not yet supported._

### ECDSA

`ECDSA(X9ECParameters|String curve, Binary digest = SHA256Binary())`\
Create an ECDSA object using [Bouncy Castle's X9ECParameters](https://people.eecs.berkeley.edu/~jonah/bc/org/bouncycastle/asn1/x9/X9ECParameters.html) or a String
to specify the curve and [Bouncy Castle's Binary](https://people.eecs.berkeley.edu/~jonah/bc/org/bouncycastle/crypto/Binary.html)
to specify the hash algorithm, with default one being SHA-256.

### Ed25519

`Ed25519()`\
Create an ed25519 object.

### Example usages

Create an `ECDSA` object, using `secp256k1` curve with default `SHA-256` digest, create a KeyPair, sign a message and verify it.

```java
ECDSA secp256k1 = new ECDSA(SECNamedCurves.getByName("secp256k1"));

KeyPair myKeyPair = secp256k1.keyPair();
byte[] myMessage = "Hello".getBytes();
byte[] mySignature = secp256k1.signDetached(myMessage, myKeyPair);

secp256k1.verify(myMessage, mySignature, myKeyPair) // True
```

Create an `ECDSA` object, using `secp256r1` curve with custom `SHA-512` digest, and create a KeyPair from pre-existing private key.

```java
X9ECParameters curve = SECNamedCurves.getByName("secp256r1")
ECDSA secp256r1 = new ECDSA(curve, new SHA512Digest());

byte[] mySecretKey = Base64.getDecoder().decode("MHQCAQEEIEa56GG2PTUJyIt4FydaMNItYsjNj6ZIbd7jXvDY4ElfoAcGBSuBBAAKoUQDQgAEJQDn8/vd8oQpA/VE3ch0lM6VAprOTiV9VLp38rwfOog3qUYcTxxX/sxJl1M4HncqEopYIKkkovoFFi62Yph6nw==");

KeyPair myKeyPair = secp256r1.keyPairFromSecretKey(mySecretKey);
```

Create an `Ed25519` object, create a KeyPair, sign a message and verify it.

```java
Ed25519 ed25519 = new Ed25519();

KeyPair myKeyPair = ed25519.keyPair();
byte[] myMessage = "Hello".getBytes();
byte[] mySignature = ed25519.signDetached(myMessage, myKeyPair);

ed25519.verify(myMessage, mySignature, myKeyPair) // True
```

## Hashing

`Hasher(MessageDigest|String algorithm)`\
Create a Hasher object, using [Java's MessageDigest](https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/security/MessageDigest.html) or using String to specify the algortihm.

`Binary hash(byte[]|String msg)`\
Hash a byte array or a String.

### Example usages

Create a `Hasher` object, using `SHA-256` algorithm, hash a message and encode it to hex.

```java
Hasher sha256 = new Hasher("SHA-256");
Binary mySHA256Digest = sha256.hash("my message");
String mySHA256HexEncodedBinary = mySHA256Digest.getHex();
```

Create a `Hasher` object, using `Keccak-384` algorithm, hash a message and encode it to base58.

```java
Hasher keccak384 = new Hasher("Keccak-384");
String myKeccak384Base58EncodedDigest = keccak384.hash("my message").getBase58();
```

## Helper Types

### Binary

`Binary(byte[] binary)`\
Create a Binary object, using byte array.

`byte[] getBinary()`\
Get raw byte array encoding of the Binary.

`String getHex()`\
Get hex encoding of the Binary.

`String getBase58()`\
Get base58 encoding of the Binary.

`String getBase64()`\
Get base64 encoding of the Binary.

### KeyPair

`KeyPair(byte[]|Binary publicKey, byte[]|Binary privateKey)`\
Create a KeyPair object, using a byte array or a Binary representation of the keys.

`Binary getPublicKey()`\
Get Binary of the public key.

`Binary getPrivateKey()`\
Get Binary of the private key.
