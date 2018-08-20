package eu.prismacloud.primitives.zkpgs.keys;

import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.crypto.Group;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRGroup;
import java.io.Serializable;
import java.math.BigInteger;

public class SignerPublicKey implements Serializable, IPublicKey {

  private static final long serialVersionUID = 7953446087582080777L;
  private final KeyGenParameters keyGenParameters;
  private final BigInteger modN;
  private final GroupElement baseR;
  private final GroupElement baseR_0;
  private final GroupElement baseS;
  private final GroupElement baseZ;
  private final QRGroup qrGroup;

/** TODO add QRGroup in both pk and sk */
  public SignerPublicKey(
      final BigInteger modN,
      final GroupElement baseR,
      final GroupElement baseR_0,
      final GroupElement baseS,
      final GroupElement baseZ,
      final QRGroup qrGroup,
      final KeyGenParameters keyGenParameters) {
    this.modN = modN;
    this.baseR = baseR;
    this.baseR_0 = baseR_0;
    this.baseS = baseS;
    this.baseZ = baseZ;
    this.qrGroup = qrGroup;
    this.keyGenParameters = keyGenParameters;
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

  public Group getQRGroup() {
    return qrGroup;
  }

  public KeyGenParameters getKeyGenParameters() {
    return keyGenParameters;
  }
}
