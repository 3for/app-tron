# java-tron ML-DSA verifier

These small Java entry points independently verify ML-DSA-44 signatures emitted
by the app-tron PoC using java-tron's `MLDSA44.verify` implementation.

- `LedgerMldsaFileVerify` reads the binary artifacts written by
  `tests/pq_poc_probe.py --output-dir ...`.
- `LedgerMldsaVerify` accepts the public key, 32-byte message and signature as
  hexadecimal command-line arguments.

The verifier message must be `SHA256(transaction.raw_data)`, stored by the
probe as `message_hash.bin`. Do not pass `raw_data.bin` directly.

## Build

First compile the `crypto` module in the PQ-enabled java-tron checkout. Then
point this Gradle project at that checkout:

```sh
JAVA_TRON_DIR=/path/to/java-tron gradle -p tron-pq-verify classes
```

The checkout can alternatively be supplied with
`-PjavaTronDir=/path/to/java-tron`. The build intentionally compiles against
the java-tron `crypto` module output so the check exercises java-tron's real
`MLDSA44.verify` entry point. Bouncy Castle 1.84 is resolved by Gradle.

## Verify probe artifacts

```sh
JAVA_TRON_DIR=/path/to/java-tron \
  gradle -p tron-pq-verify run --args="\
    /tmp/tron-mldsa-poc/public_key.bin \
    /tmp/tron-mldsa-poc/message_hash.bin \
    /tmp/tron-mldsa-poc/signature.bin"
```

Expected output:

```text
pk=1312 message=32 signature=2420 valid=true
```
