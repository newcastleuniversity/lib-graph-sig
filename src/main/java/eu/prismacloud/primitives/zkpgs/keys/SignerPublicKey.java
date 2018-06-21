package eu.prismacloud.primitives.zkpgs.keys;

import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.math.BigInteger;

public class SignerPublicKey {

  private SignerPrivateKey privateKey;
  private BigInteger N;
  private GroupElement R;
  private GroupElement R_0;
  private GroupElement S;
  private GroupElement Z;

  public SignerPublicKey(final SignerPrivateKey privateKey, final KeyGenParameters gs_params) {

    /* TODO add unique identifier to key */
    /* TODO initialize and Compute public key for signer */

    this.privateKey = privateKey;
    // this.gs_params = gs_params;

  }

  public SignerPublicKey(
      final BigInteger N,
      final GroupElement R,
      final GroupElement R_0,
      final GroupElement S,
      final GroupElement Z) {
    this.N = N;
    this.R = R;
    this.R_0 = R_0;
    this.S = S;
    this.Z = Z;
  }

  public BigInteger getN() {
    return N;
  }

  public GroupElement getR_0() {
    return R_0;
  }

  public GroupElement getS() {
    return S;
  }

  public GroupElement getZ() {
    return Z;
  }

  public GroupElement getR() {
    return this.R;
  }
}
