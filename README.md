# Finnick
Finnick is a *proof of concept* for how you can turn a duplex-style AEAD scheme (e.g., [AEGIS](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aegis-aead)) into a memory-hard password-based KDF.

> [!CAUTION]
> This is an experimental construction that has not been properly thought through, researched, or peer reviewed. The design may also change at any time if I continue to work on it. Therefore, it **MUST NOT** be used in production.

## Design
### External Function
1. Hash the `password`, `salt`, `pepper`, `associatedData`, and their little-endian encoded lengths to derive a key using a collision-resistant hash function. The `pepper` could be used as the key parameter for a keyed hash function (meaning no length encoding for it), with the key set to zeros otherwise.
2. Call the internal function in parallel `parallelism` times. Use the loop iteration for domain separation in the internal function.
3. XOR the outputs together. This can be skipped if there's only one output.
4. Encrypt a `length`-sized buffer of zeros using the AEAD scheme, with the derived key as the key, the `memorySize`/`iterations`/`parallelism`/domain separation from the internal function encoded into the nonce, and the XOR of the outputs as associated data. Note that this assumes the AEAD scheme is [context committing](https://eprint.iacr.org/2023/526); see the [Rationale](#rationale) section for alternatives if it isn't. The domain separation could be the last byte or the loop iteration portion of the nonce set to `0x00`, for example.
5. Return the ciphertext (truncated to remove the tag if using an AEAD with finalization rather than an AEAD without finalization) as the derived key material.

### Internal Function
1. Create an all-zero buffer of the specified `memorySize`.
2. Fill the buffer with pseudorandom bytes by encrypting it with the AEAD scheme. The `memorySize`, `iterations`, `parallelism`, and `parallelismIteration` can be little-endian encoded into part of the nonce, with the rest used as a counter. This might be tight with a 128-bit nonce, although `iterations` could probably be `uint16` and `parallelism`/`parallelismIteration` could probably be 1-byte each.
3. Split the buffer into large blocks (e.g., 1024-8192 bits). Encrypt each block, incrementing the counter, with the previous block plus 3+ random blocks as associated data. The first previous block is the last block of the filled buffer from step 2.
4. For the first half of the first iteration, use a data-independent access pattern. For example, encrypt zeros to retrieve some pseudorandom bytes, and then do `ReadUInt64LittleEndian(pseudorandom[0..8]) % blockCount` or similar to get each random block index (be aware of modulo bias - use `uint128` or make `blockCount` a power of 2). This could be precomputed rather than in the loop so you only have to do one AEAD call. Importantly, the key must not depend on the password, so it should either be all-zero, derived from the salt (via collision-resistant hashing), or derived from the `memorySize`/`iterations`/`parallelism`/`parallelismIteration` and possibly a `context` string specifying the name of the application/service.
5. For the rest of that iteration and other iterations, use a data-dependent access pattern. This means taking the pseudorandom bytes from the previous block within the loop.
6. This is done until the whole buffer has been processed. Then this is repeated `iteration` number of times.
7. Return the last block of the buffer to the external function.

### Rationale
- Variable-length inputs must have their lengths encoded to avoid [canonicalization attacks](https://soatok.blog/2021/07/30/canonicalization-attacks-against-macs-and-signatures/).
- The hashing should be collision resistant to make it computationally infeasible to find another `(password, salt, pepper, associatedData)` that produces the same password hash. However, this probably also requires the AEAD scheme to be [key committing](https://eprint.iacr.org/2022/268).
- The internal function calls must be domain separated to produce distinct outputs.
- XORing the outputs is more efficient than concatenation and still means you need to have computed all the outputs.
- Domain separation is required when computing the derived key material to avoid producing the same ciphertext as in the internal function. This is better than just relying on a difference in associated data length.
- If using an AEAD scheme, the tag may not be suitable as derived key material, which is why it's being truncated. To be honest, you could just remove the finalization from the AEAD scheme and treat it as a stream cipher, avoiding this problem.
- Encoding the parameters and using a counter in the nonce makes for efficient domain separation that resembles ordinary AEAD usage and ensures that the nonce doesn't repeat, enabling distinct outputs.
- Assuming a 128-bit nonce, if you did `LE32(memorySize)`, `LE16(iterations)`, `(byte)parallelism`, and `(byte)parallelismIteration`, that leaves `LE64(counter)`. If there's support for a larger nonce, `LE32()` could be used for all the parameters besides the counter. A 64-bit counter won't overflow if you limit `memorySize` and `iterations` appropriately.
- You want large blocks for memory-hardness and performance reasons. It should probably be a multiple of a cache line (e.g., 1024 or 2048 bits).
- With duplex-style AEAD schemes, the associated data is absorbed into the state before encryption, meaning it affects the ciphertext output.
- Without a [context committing](https://eprint.iacr.org/2023/526) AEAD scheme like [Ascon](https://tosc.iacr.org/index.php/ToSC/article/view/11295), you might think the attacker could implement the algorithm in a way that eliminates the memory-hardness by using the associated data parameter to cause [state collisions](https://tosc.iacr.org/index.php/ToSC/article/view/11404/). However, for most of the algorithm, I don't think this is a problem since intermediate ciphertexts aren't output/known to the attacker. In other words, the attacker has no target states to aim for without first running the algorithm, at which point there's no purpose to performing an attack since you've just tested that password.
- Where AEAD commitment does matter is the final key derivation since the attacker knows the password hash. If you feed the XORed outputs in as associated data, the AEAD needs to be context committing. If you hash the key and XORed outputs to derive a subkey, the AEAD needs to be key committing (since this is [Hash-then-Encrypt](https://eprint.iacr.org/2022/268)). If the AEAD scheme isn't even key committing (most algorithms), you probably have to use the hash function for key derivation because the [key commitment fixes](https://www.usenix.org/conference/usenixsecurity22/presentation/albertini) don't apply in this context seeing as they require verifying a tag/commitment. Alternatively, you could modify [certain AEAD schemes](https://eprint.iacr.org/2023/1525) to be more like [Ascon](https://tosc.iacr.org/index.php/ToSC/article/view/11295).
- 3+ random blocks comes from [Balloon](https://crypto.stanford.edu/balloon/). Ideally, you should use more than that (e.g., 6 or 7), but it will affect the performance. The idea is to avoid merely processing the blocks in order as that's not memory-hard. The random blocks aren't XORed together, which would be more efficient and would allow more random blocks to be used, to force storage of them in memory.
- A data-independent and data-dependent access pattern is used like [Argon2id](https://datatracker.ietf.org/doc/html/rfc9106) because this seems like the best of both worlds and is more efficient/stronger than being entirely data-independent. Either the first half of the first iteration or the entire first iteration should be used for data-independent access, and the former makes sense if you want to support 1 iteration.
- Taking the pseudorandom bytes from the previous block for data-dependent access works because you've just updated the previous block, meaning it depends on the password.
- Returning the last block of the buffer requires the attacker running the entire function.

## Strengths
- Inspired by [Balloon](https://crypto.stanford.edu/balloon/), which has been proven memory-hard.
- Uses a hybrid memory access pattern for better GPU/ASIC resistance whilst having some resistance against side-channel attacks.
- Has the potential to be more efficient than Balloon. The block size is more flexible, you can use an [AES-based scheme](https://eprint.iacr.org/2023/523), duplex-based AEADs can have a [larger rate](https://www.hyperelliptic.org/DIAC/slides/PermutationDIAC2012.pdf) (and [smaller capacity](https://ascon.iaik.tugraz.at/specification.html)) than the unkeyed sponge construction, and keyed constructions can also use fewer rounds to boost performance.
- Simple to understand and implement if a proper specification/reference implementation is written.

## Limitations
- This might be insecure or not particularly memory-hard.
- This requires two algorithms, namely a collision-resistant hash function and an AEAD scheme (with or without finalization). However, they could both rely on the same permutation (e.g., [Keccak-f](https://keccak.team/keccak.html) or [Ascon](https://ascon.iaik.tugraz.at/specification.html)).
- The AEAD scheme must be duplex-style and should probably be key or context committing, which is rare for [popular algorithms](https://eprint.iacr.org/2023/526) and even [newer proposals](https://eprint.iacr.org/2023/1525). Ideally, AES-based schemes should be used for performance, although that's bad for devices without [AES instructions](https://en.wikipedia.org/wiki/AES_instruction_set) and I'm [not sure](https://eprint.iacr.org/2024/901) if any of these are context committing. However, it's very doable to construct a context committing scheme using Keccak, and there's also the theoretical [OCH](https://csrc.nist.gov/csrc/media/Events/2023/third-workshop-on-block-cipher-modes-of-operation/documents/accepted-papers/Flexible%20Authenticated%20Encryption.pdf) with [Simpira](https://eprint.iacr.org/2016/122).
- The performance is almost certainly worse than Argon2, especially if you increase the number of random blocks for more memory-hardness. You can't cache the initialized state either because of the different nonces. However, the block size and algorithms are flexible.
- This isn't cache-hard, which is [reportedly](https://en.wikipedia.org/wiki/Bcrypt#Comparison_to_other_password_hashing_algorithms) preferable for short runtimes. These algorithms involve many small, fast pseudorandom reads/table lookups (e.g., 64 bits rather than 1024 bits). This forces GPUs to use less memory bandwidth because of their large bus widths ([typically 256 to 1024 bits](https://www.techpowerup.com/gpu-specs/?sort=name)). For some reason, no academics seem to have looked into this, only [PHC](https://www.password-hashing.net/) people.
- A data-independent and data-dependent access pattern offers less protection against cache-timing attacks than a fully data-independent algorithm. However, there seems to be a general dislike of fully data-independent algorithms due to their worse GPU/ASIC resistance.
- The max parameters/counter size are limited by the AEAD nonce size.
- Avoiding modulo bias either requires using power of 2 memory sizes or `uint128` and the [Simple Modular Method](https://crypto.stackexchange.com/questions/5708/creating-a-small-number-from-a-random-octet-string/50569#50569). The former is less flexible in terms of user choice, and the latter requires more output (this should only affect data-independent access).

## Open Questions
- Is there a way to only use an AEAD scheme rather than two algorithms? The problem is deriving an initial key. Maybe an AEAD tag computed over the password and salt could be used as the derived key. Perhaps the tag could be encrypted/masked somehow to ensure it's uniformly random/appropriate key material.
- Should you fill the initial buffer by encrypting a block at a time or the entire buffer at once?
- Am I right about AEAD commitment here?
- What's the best block size to use?
- What are the best algorithms to use? Or what's the best permutation to use? Should AES be avoided? Should the rounds be reduced to improve performance?
- Is a hybrid mode worth it? Besides Argon2id, the most popular algorithms are data-dependent.
- Should the data-independent memory access pattern depend on the salt? I believe it's [more resistant to attacks but can leak metadata](https://crypto.stackexchange.com/q/112565). Maybe this resistance is less important with a hybrid mode.
- How can some cache-hardness be added like [Argon2ds](https://www.password-hashing.net/argon2-specs.pdf) and [yescrypt](https://www.password-hashing.net/submissions/specs/yescrypt-v2.pdf)? Is it worth it for the performance penalty or are you better off just using a fully cache-hard algorithm, which should be [fast](https://youtu.be/VwzNw018ETc)?

