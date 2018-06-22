package eu.prismacloud.primitives.zkpgs.keys;

import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.math.BigInteger;

public class SignerPublicKey  {

  private SignerPrivateKey privateKey;
  private BigInteger modN;
  private GroupElement baseR;
  private GroupElement baseR_0;
  private GroupElement baseS;
  private GroupElement baseZ;

  public SignerPublicKey(final SignerPrivateKey privateKey, final KeyGenParameters gs_params) {

    /* TODO add unique identifier to key */
    /* TODO initialize and Compute public key for signer */

    this.privateKey = privateKey;
    // this.gs_params = gs_params;

  }

  public SignerPublicKey(
      final BigInteger modN,
      final GroupElement baseR,
      final GroupElement baseR_0,
      final GroupElement baseS,
      final GroupElement baseZ) {
    this.modN = modN;
    this.baseR = baseR;
    this.baseR_0 = baseR_0;
    this.baseS = baseS;
    this.baseZ = baseZ;
  }

  public BigInteger getModN() {
    return modN;
  }

  public GroupElement getBaseR_0() {
    return baseR_0;
  }

  public GroupElement getBaseS() {
    return baseS;
  }

  public GroupElement getBaseZ() {
    return baseZ;
  }

  public GroupElement getBaseR() {
    return this.baseR;
  }
}
