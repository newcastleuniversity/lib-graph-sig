package eu.prismacloud.primitives.zkpgs.keys;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.encoding.GraphEncoding;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.Group;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElementPQ;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRGroupN;
import java.math.BigInteger;
import java.util.Map;

/** Class representing the extended key pair */
public final class ExtendedKeyPair {

  private final SignerPublicKey publicKey;
  private final SignerPrivateKey privateKey;
  private final GraphEncodingParameters graphEncodingParameters;
  private final KeyGenParameters keyGenParameters;
  private final GroupElement baseS;
  private final BigInteger modN;
  private final SignerKeyPair signerKeyPair;
  private ExtendedPublicKey extendedPublicKey;
  private ExtendedPrivateKey extendedPrivateKey;
  private int index = 0;
  private BaseRepresentation base;
  private Map<URN, BaseRepresentation> baseRepresentationMap;
  private Map<URN, BigInteger> discLogOfEdgeBases;
  private Map<URN, BigInteger> vertexRepresentatives;
  private BigInteger vertexPrimeRepresentative;
  private Map<URN, BigInteger> discLogOfVertexBases;
  private Map<URN, BigInteger> labelRepresentatives;
  private GraphEncoding graphEncoding;

  /**
   * Instantiates a new Extended key pair.
   *
   * @param signerKeyPair the signer key pair
   * @param graphEncodingParameters the graph encoding parameters
   * @param keyGenParameters the key gen parameters
   */
  public ExtendedKeyPair(
      final SignerKeyPair signerKeyPair,
      final GraphEncodingParameters graphEncodingParameters,
      final KeyGenParameters keyGenParameters) {

    this.signerKeyPair = signerKeyPair;
    this.publicKey = signerKeyPair.getPublicKey();
    this.privateKey = signerKeyPair.getPrivateKey();
    this.graphEncodingParameters = graphEncodingParameters;
    this.keyGenParameters = keyGenParameters;
    this.baseS = signerKeyPair.getPublicKey().getBaseS();
    this.modN = signerKeyPair.getPublicKey().getModN();
  }

  /**
   * Gets extended public key.
   *
   * @return the extended public key
   */
  public ExtendedPublicKey getExtendedPublicKey() {
    return extendedPublicKey;
  }

  /**
   * Gets extended private key.
   *
   * @return the extended private key
   */
  public ExtendedPrivateKey getExtendedPrivateKey() {
    return extendedPrivateKey;
  }

  /**
   * Gets public key.
   *
   * @return the public key
   */
  public SignerPublicKey getPublicKey() {
    return publicKey;
  }

  /**
   * Gets private key.
   *
   * @return the private key
   */
  public SignerPrivateKey getPrivateKey() {
    return privateKey;
  }

  /**
   * Graph encoding setup graph encoding.
   *
   * @return the graph encoding
   */
  public GraphEncoding graphEncodingSetup() {

    graphEncoding =
        GraphEncoding.graphEncodingSetup(
            baseRepresentationMap,
            vertexRepresentatives,
            publicKey,
            keyGenParameters,
            graphEncodingParameters);

    return graphEncoding;
  }

  /**
   * Gets graph encoding.
   *
   * @return the graph encoding
   */
  public GraphEncoding getGraphEncoding() {
    return this.graphEncoding;
  }

  /** Certify prime representatives. */
  public void certifyPrimeRepresentatives() {
    Group qrGroup = signerKeyPair.getQRGroup();
    BigInteger x_R_V = qrGroup.createElement().getValue();

    GroupElement R_V = baseS.modPow(x_R_V, modN);

    BaseRepresentation baseV = new BaseRepresentation(R_V, 0, BASE.VERTEX);

    BigInteger x_R_L = qrGroup.createElement().getValue();

    GroupElement R_L = baseS.modPow(x_R_L, modN);

    BaseRepresentation baseL = new BaseRepresentation(R_L, 0, BASE.VERTEX);

    GraphEncoding.certify(vertexRepresentatives, baseV, labelRepresentatives, baseL);
  }

  /**
   * Generate edge baseRepresentationMap.
   *
   * @param S the quadratic group generator S
   * @param modN the modulus N
   * @param qrGroup the quadratic residue group
   */
  public void generateEdgeBases(
      final QRElementPQ S, final BigInteger modN, final QRGroupN qrGroup) {
    BigInteger x_R_ij;
    GroupElement R_ij;

    for (int j = 0; j < graphEncodingParameters.getL_E(); j++) {
      index++;
      x_R_ij = qrGroup.createElement().getValue();
      R_ij = S.modPow(x_R_ij, modN);

      base = new BaseRepresentation(R_ij, index, BASE.EDGE);

      baseRepresentationMap.put(
          URN.createZkpgsURN("baseRepresentationMap.edge.R_i_j_" + index), base);
      discLogOfEdgeBases.put(URN.createZkpgsURN("discretelogs.edge.R_i_j_" + index), x_R_ij);
    }
  }

  /**
   * Generate vertex baseRepresentationMap.
   *
   * @param S the quadratic group generator S
   * @param modN the modulus N
   * @param qrGroup the quadratic residue group
   */
  public void generateVertexBases(
      final QRElementPQ S, final BigInteger modN, final QRGroupN qrGroup) {
    BigInteger x_Ri;
    GroupElement R_i;

    for (int i = 0; i < graphEncodingParameters.getL_V(); i++) {
      index++;
      x_Ri = qrGroup.createElement().getValue();
      R_i = S.modPow(x_Ri, modN);
      base = new BaseRepresentation(R_i, index, BASE.VERTEX);
      baseRepresentationMap.put(
          URN.createZkpgsURN("baseRepresentationMap.vertex.R_i_" + index), base);

      vertexPrimeRepresentative =
          CryptoUtilsFacade.generateRandomPrime(graphEncodingParameters.getlPrime_L());

      vertexRepresentatives.put(
          URN.createZkpgsURN("vertex.representative.e_i_" + i), vertexPrimeRepresentative);

      discLogOfVertexBases.put(URN.createZkpgsURN("discretelogs.vertex.R_i_" + index), x_Ri);
    }
  }

  /**
   * Gets label representatives.
   *
   * @return the label representatives
   */
  public Map<URN, BigInteger> getLabelRepresentatives() {
    return labelRepresentatives;
  }

  private void createExtendedPrivateKey() {
    this.extendedPrivateKey =
        new ExtendedPrivateKey(privateKey, discLogOfVertexBases, discLogOfEdgeBases);
  }
}
