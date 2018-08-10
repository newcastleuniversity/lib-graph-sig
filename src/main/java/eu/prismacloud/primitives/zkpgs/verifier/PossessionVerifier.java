package eu.prismacloud.primitives.zkpgs.verifier;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElement;
import java.math.BigInteger;
import java.util.logging.Logger;

/** */
public class PossessionVerifier implements IVerifier {

  private ExtendedPublicKey extendedPublicKey; // implements IVerifier{}
  private ProofStore<Object> proofStore;
  private KeyGenParameters keyGenParameters;
  private GroupElement baseZ;
  private GroupElement baseS;
  private BaseCollection baseCollection;
  private GroupElement baseR0;
  private BaseIterator vertexIterator;
  private BaseIterator edgeIterator;
  private GroupElement APrime;
  private BigInteger cChallenge;
  private BigInteger hatvPrime;
  private BigInteger hate;
  private GroupElement hatZ;
  private BigInteger hatm_0;
  private Logger gslog = GSLoggerConfiguration.getGSlog();

  public GroupElement computeHatZ(
      final ExtendedPublicKey extendedPublicKey,
      final ProofStore<Object> proofStore,
      final KeyGenParameters keyGenParameters) {
    this.extendedPublicKey = extendedPublicKey;
    this.proofStore = proofStore;
    this.keyGenParameters = keyGenParameters;
    this.baseZ = extendedPublicKey.getPublicKey().getBaseZ();
    this.baseS = extendedPublicKey.getPublicKey().getBaseS();
    this.baseCollection = extendedPublicKey.getBaseCollection();
    this.vertexIterator = baseCollection.createIterator(BASE.VERTEX);
    this.edgeIterator = baseCollection.createIterator(BASE.EDGE);
    this.baseR0 = extendedPublicKey.getPublicKey().getBaseR_0();

    APrime = (GroupElement) proofStore.retrieve("verifier.APrime");
    cChallenge = (BigInteger) proofStore.retrieve("verifier.c");
    hate = (BigInteger) proofStore.retrieve("verifier.hate");
    hatvPrime = (BigInteger) proofStore.retrieve("verifier.hatvPrime");
    hatm_0 = (BigInteger) proofStore.retrieve("verifier.hatm_0");

    QRElement basesProduct = (QRElement) extendedPublicKey.getPublicKey().getQRGroup().getOne();

    //    BaseIterator baseIterator = baseCollection.createIterator(BASE.ALL);
    //    for (BaseRepresentation baseRepresentation : baseIterator) {
    //      basesProduct =
    //          basesProduct.multiply(
    //              baseRepresentation.getBase().modPow(baseRepresentation.getExponent()));
    //    }
        GroupElement baseR0hatm_0 = baseR0.modPow(hatm_0);
    gslog.info("Aprime: " + APrime);
    GroupElement aPrimeMulti =
        APrime.modPow(
            NumberConstants.TWO
                .getValue()
                .pow(keyGenParameters.getL_e() - 1)); // keyGenParameters.getLowerBoundE());

    GroupElement divide = baseZ.multiply(aPrimeMulti.modInverse());
    GroupElement result = divide.modPow(cChallenge.negate());
    GroupElement aPrimeHate = APrime.modPow(hate);
    GroupElement baseShatvPrime = baseS.modPow(hatvPrime);

    gslog.info("aPrimehate bitlength: " + aPrimeHate.bitLength());
    hatZ = result.multiply(aPrimeHate).multiply(baseShatvPrime).multiply(baseR0hatm_0);
        //basesProduct
//            .multiply(result)
            //            .multiply(baseR0hatm_0)
//            .multiply(aPrimeHate)
//            .multiply(baseShatvPrime);

    gslog.info("hatZ: " + hatZ);
    gslog.info("hatZ bitlength: " + hatZ.bitLength());

    return hatZ;
  }
}
