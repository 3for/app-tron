import org.tron.common.crypto.pqc.MLDSA44;

/** Verify Ledger ML-DSA-44 output with java-tron's implementation using hex arguments. */
public final class LedgerMldsaVerify {
  private LedgerMldsaVerify() {}

  private static byte[] decodeHex(String hex) {
    if ((hex.length() & 1) != 0) {
      throw new IllegalArgumentException("odd hex length");
    }

    byte[] output = new byte[hex.length() / 2];
    for (int i = 0; i < output.length; i++) {
      int high = Character.digit(hex.charAt(i * 2), 16);
      int low = Character.digit(hex.charAt(i * 2 + 1), 16);
      if (high < 0 || low < 0) {
        throw new IllegalArgumentException("invalid hex");
      }
      output[i] = (byte) ((high << 4) | low);
    }
    return output;
  }

  public static void main(String[] args) {
    if (args.length != 3) {
      throw new IllegalArgumentException("expected public-key, message and signature hex");
    }

    byte[] publicKey = decodeHex(args[0]);
    byte[] message = decodeHex(args[1]);
    byte[] signature = decodeHex(args[2]);
    verify(publicKey, message, signature);
  }

  static void verify(byte[] publicKey, byte[] message, byte[] signature) {
    boolean valid = MLDSA44.verify(publicKey, message, signature);
    System.out.printf(
        "pk=%d message=%d signature=%d valid=%s%n",
        publicKey.length,
        message.length,
        signature.length,
        valid);
    if (!valid) {
      throw new IllegalStateException("java-tron rejected Ledger ML-DSA signature");
    }
  }
}
