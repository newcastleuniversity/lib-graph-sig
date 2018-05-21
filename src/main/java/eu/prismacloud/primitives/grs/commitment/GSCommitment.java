package eu.prismacloud.primitives.grs.commitment;

import eu.prismacloud.primitives.grs.keys.SignerPublicKey;
import java.math.BigInteger;

public class GSCommitment implements ICommitment {
  private BigInteger capR;
  private BigInteger capS;
  private BigInteger n;
  private int basesNumber;

  private final BigInteger value;

  public GSCommitment(final BigInteger value, final SignerPublicKey spk) {
    /* TODO create a commitment */
    this.value = value;
  }

  public BigInteger getCommitment() {
    return value;
  }

  //    public BigInteger getCapR() {
  //        return null;
  //    }
  //
  //    public BigInteger getCapS() {
  //        return null;
  //    }
  //
  //    public BigInteger getN() {
  //        return null;
  //    }
  //
  //    public int getNumBases() {
  //        return 0;
  //    }
}
