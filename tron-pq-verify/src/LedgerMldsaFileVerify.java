import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Verify the binary artifacts emitted by tests/pq_poc_probe.py. */
public final class LedgerMldsaFileVerify {
  private LedgerMldsaFileVerify() {}

  public static void main(String[] args) throws IOException {
    if (args.length != 3) {
      throw new IllegalArgumentException(
          "expected public-key, message and signature file paths");
    }

    byte[] publicKey = Files.readAllBytes(Path.of(args[0]));
    byte[] message = Files.readAllBytes(Path.of(args[1]));
    byte[] signature = Files.readAllBytes(Path.of(args[2]));
    LedgerMldsaVerify.verify(publicKey, message, signature);
  }
}
