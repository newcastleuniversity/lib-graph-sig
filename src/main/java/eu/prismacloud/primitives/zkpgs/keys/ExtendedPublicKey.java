package eu.prismacloud.primitives.zkpgs.keys;

import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.JsonIsoCountries;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.Group;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.math.BigInteger;
import java.util.Map;

/** The type Extended public key. */
public class ExtendedPublicKey {
  private final SignerKeyPair signerKeyPair;
  private ExtendedPublicKey ePublicKey;
  private ExtendedPrivateKey ePrivateKey;
  private Map<URN, GroupElement> vertexBases;
  private Map<URN, GroupElement> edgeBases;
  private Map<URN, BigInteger> discLogOfVertexBases;
  private Map<URN, BigInteger> discLogOfEdgeBases;
  private final KeyGenParameters keygenParams;
  private final GraphEncodingParameters graphEncodingParameters;
  private JsonIsoCountries jsonIsoCountries;
  private Map<URN, BigInteger> countryLabels;

  /**
   * Instantiates a new Extended public key.
   *
   * @param signerKeyPair the signer key pair
   * @param keygenParams the keygen params
   * @param graphEncodingParameters the graph encoding parameters
   */
  public ExtendedPublicKey(
      final SignerKeyPair signerKeyPair,
      final KeyGenParameters keygenParams,
      final GraphEncodingParameters graphEncodingParameters) {

    this.signerKeyPair = signerKeyPair;
    this.keygenParams = keygenParams;
    this.graphEncodingParameters = graphEncodingParameters;
  }

  /**
   * Gets public key.
   *
   * @return the public key
   */
  public SignerPublicKey getPublicKey() {
    return this.signerKeyPair.getPublicKey();
  }

  /**
   * Gets vertex bases.
   *
   * @return the vertex bases
   */
  public Map<URN, GroupElement> getVertexBases() {
    return this.vertexBases;
  }

  /**
   * Gets edge bases.
   *
   * @return the edge bases
   */
  public Map<URN, GroupElement> getEdgeBases() {
    return this.edgeBases;
  }

  /** Graph encoding setup. */
  public void graphEncodingSetup() {
    GroupElement S;
    BigInteger modN;

    Group qrGroup = signerKeyPair.getQRGroup();
    S = signerKeyPair.getPublicKey().getS();
    modN = qrGroup.getModulus();

    generateVertexBases(S, modN, qrGroup);

    generateEdgeBases(S, modN, qrGroup);

    jsonIsoCountries = new JsonIsoCountries();

    countryLabels = jsonIsoCountries.getCountryMap();

    createExtendedPrivateKey();
  }

  /**
   * Generate edge bases.
   *
   * @param S the quadratic group generator S
   * @param modN the modulus N
   * @param qrGroup the quadratic residue group
   */
  public void generateEdgeBases(final GroupElement S, final BigInteger modN, final Group qrGroup) {
    BigInteger x_Rj;
    GroupElement R_j;

    for (int j = 0; j < graphEncodingParameters.getL_E(); j++) {
      x_Rj = qrGroup.createElement().getValue();
      R_j = S.modPow(x_Rj, modN);

      edgeBases.put(URN.createZkpgsURN("bases.edge.R_" + j), R_j);
      discLogOfEdgeBases.put(URN.createZkpgsURN("exponents.edge.R_" + j), x_Rj);
    }
  }

  /**
   * Generate vertex bases.
   *
   * @param S the quadratic group generator S
   * @param modN the modulus N
   * @param qrGroup the quadratic residue group
   */
  public void generateVertexBases(
      final GroupElement S, final BigInteger modN, final Group qrGroup) {
    BigInteger x_Ri;
    GroupElement R_i;
    for (int i = 0; i < graphEncodingParameters.getL_V(); i++) {
      x_Ri = qrGroup.createElement().getValue();
      R_i = S.modPow(x_Ri, modN);

      vertexBases.put(URN.createZkpgsURN("bases.vertex.R_" + i), R_i);
      discLogOfVertexBases.put(URN.createZkpgsURN("exponents.vertex.R_" + i), x_Ri);
    }
  }

  /**
   * Gets country labels .
   *
   * @return the country labels
   */
  public Map<URN, BigInteger> getCountryLabels() {
    return countryLabels;
  }

  private void createExtendedPrivateKey() {
    ePrivateKey =
        new ExtendedPrivateKey(
            signerKeyPair.getPrivateKey(), discLogOfVertexBases, discLogOfEdgeBases);
  }
}
