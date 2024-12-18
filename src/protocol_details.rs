/*!
A very brief summary of the papers and RFCs of SRP6 and SRP6a

## SRP Vocabulary

```plain
N    A large safe prime                     (N = 2q+1, where q is prime)
     All arithmetic is done modulo N.
g    A generator modulo N
k    Multiplier parameter                   (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
s    User's salt
I    Username                               (the rfc calls it U)
p    Cleartext Password
H()  One-way hash function
^    (Modular) Exponentiation
u    Random scrambling parameter
a,b  Secret ephemeral values
A,B  Public ephemeral values
x    Private key                            (derived from p and s)
v    Password verifier
S    Session key
K    Strong session key                     (SHA1 interleaved)
M    Proof (calculated by the server)
M1   Proof provided by the client
```

## SRP Formulas

Calculations by the client:
```plain
I, p = <read from user>
N, g, s, B = <read from server>
a = random()
A = g^a % N
u = SHA1(PAD(A) | PAD(B))
k = SHA1(N | PAD(g))                        (k = 3 for legacy SRP-6)
x = SHA1(s | SHA1(I | ":" | p))
S = (B - (k * g^x)) ^ (a + (u * x)) % N
K = SHA_Interleave(S)
M = H(H(N) XOR H(g) | H(U) | s | A | B | K)
```

Calculations by the server:
```plain
N, g, s, v = <read from password file>
v = g^x % N
b = random()
k = SHA1(N | PAD(g))
B = k*v + g^b % N
A = <read from client>
u = SHA1(PAD(A) | PAD(B))
S = (A * v^u) ^ b % N
K = SHA_Interleave(S)

H(A | M | K)
```

## Safeguards
1. The user will abort if he receives one of
    - `B mod N == 0`
    - `u == 0`
2. The host will abort if it detects that `A mod N == 0`.
3. The user must show his proof of `K` first. If the server detects that the user's proof is incorrect, it must abort without showing its own proof of `K`.

## Test Data

run tests with the 'norand' feature to test against the data provided in RFC 5054 appendix B.

The test is called `test_official_vectors_1024`.

## References
- [EKE](https://en.wikipedia.org/wiki/Encrypted_key_exchange)
- [papers](http://srp.stanford.edu/doc.html#papers)
- [design](http://srp.stanford.edu/design.html)
- [rfc](https://datatracker.ietf.org/doc/html/rfc2945)
- [vetted N](https://datatracker.ietf.org/doc/html/rfc5054#appendix-A)
*/

/// Test values defined in RFC 5054 appendix B (for 1024 version)
#[allow(dead_code)]
pub mod testdata {
    use hex_literal::hex;

    pub const USERNAME: &str = "alice";
    pub const PASSWORD: &str = "password123";
    pub const SALT: [u8; 16] = hex!("BEB25379 D1A8581E B5A72767 3A2441EE");
    pub const VERIFIER: [u8; 128] = hex!(
        r"7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812
        9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5
        C671085A 1447B52A 48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5
        EA53D15C 1AFF87B2 B9DA6E04 E058AD51 CC72BFC9 033B564E 26480D78
        E955A5E2 9E7AB245 DB2BE315 E2099AFB"
    );

    pub const K_MULTIPLIER: [u8; 20] = hex!("7556AA04 5AEF2CDD 07ABAF0F 665C3E81 8913186F");
    pub const X: [u8; 20] = hex!("94B7555A ABE9127C C58CCF49 93DB6CF8 4D16C124");

    pub const A_PRIVATE: [u8; 32] =
        hex!("60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56 AFD529DD DA2D4393");
    pub const B_PRIVATE: [u8; 32] =
        hex!("E487CB59 D31AC550 471E81F0 0F6928E0 1DDA08E9 74A004F4 9E61F5D1 05284D20");
    pub const A_PUBLIC: [u8; 128] = hex!(
        r"61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4
        4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC
        8E393561 79EAE45E 42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44
        BE087EF0 6530E69F 66615261 EEF54073 CA11CF58 58F0EDFD FE15EFEA
        B349EF5D 76988A36 72FAC47B 0769447B"
    );
    pub const B_PUBLIC: [u8; 128] = hex!(
        r"BD0C6151 2C692C0C B6D041FA 01BB152D 4916A1E7 7AF46AE1 05393011
        BAF38964 DC46A067 0DD125B9 5A981652 236F99D9 B681CBF8 7837EC99
        6C6DA044 53728610 D0C6DDB5 8B318885 D7D82C7F 8DEB75CE 7BD4FBAA
        37089E6F 9C6059F3 88838E7A 00030B33 1EB76840 910440B1 B27AAEAE
        EB4012B7 D7665238 A8E3FB00 4B117B58"
    );
    pub const U: [u8; 20] = hex!("CE38B959 3487DA98 554ED47D 70A7AE5F 462EF019");
    pub const SECRET: [u8; 128] = hex!(
        r"B0DC82BA BCF30674 AE450C02 87745E79 90A3381F 63B387AA F271A10D
        233861E3 59B48220 F7C4693C 9AE12B0A 6F67809F 0876E2D0 13800D6C
        41BB59B6 D5979B5C 00A172B4 A2A5903A 0BDCAF8A 709585EB 2AFAFA8F
        3499B200 210DCC1F 10EB3394 3CD67FC8 8A2F39A4 BE5BEC4E C0A3212D
        C346D7E4 74B29EDE 8A469FFE CA686E5A"
    );
}
