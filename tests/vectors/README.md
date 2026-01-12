# ODI test vectors

This directory contains small ODI files used for cross implementation testing.

## odi-0.1-basic.odi

Contents:

- payload section bytes: b'PAYLOAD'
- meta section bytes: b'{}'
- manifest section bytes: b'{}'

Layout:

- header size: 56
- section entry size: 96
- section count: 3
- table offset: 56
- table length: 288
- payload offset: 344
- meta offset: 351
- manifest offset: 353

Expected SHA 256 digests:

- payload: ea36e4da4017000028db7794d946b152540d7c68bbdb6c60e999f1dce19a409b
- meta: 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
- manifest: 44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a

Expected file size: 355 bytes

Validation notes:

- All reserved fields are zero
- hash_len is 32, hash_alg is sha256
- hash field uses first 32 bytes, remaining bytes are zero
