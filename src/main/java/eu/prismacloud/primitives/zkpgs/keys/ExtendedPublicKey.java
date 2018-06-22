package eu.prismacloud.primitives.zkpgs.keys;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
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
  private Map<URN, BaseRepresentation> bases;
  private Map<URN, BigInteger> discLogOfVertexBases;
  private Map<URN, BigInteger> discLogOfEdgeBases;
  private final KeyGenParameters keygenParams;
  private final GraphEncodingParameters graphEncodingParameters;
  private JsonIsoCountries jsonIsoCountries;
  private Map<URN, BigInteger> countryLabels;
  private BaseRepresentation base;
  private int index = 0;

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
   * Gets bases.
   *
   * @return the vertex bases
   */
  public Map<URN, BaseRepresentation> getBases() {
    return this.bases;
  }

  /** Graph encoding setup. */
  public void graphEncodingSetup() {
    GroupElement S;
    BigInteger modN;

    Group qrGroup = signerKeyPair.getQRGroup();
    S = signerKeyPair.getPublicKey().getBaseS();
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
    BigInteger x_R_ij;
    GroupElement R_ij;

    for (int j = 0; j < graphEncodingParameters.getL_E(); j++) {
      index++;
      x_R_ij = qrGroup.createElement().getValue();
      R_ij = S.modPow(x_R_ij, modN);

      base = new BaseRepresentation(R_ij, x_R_ij, index, BASE.EDGE);

      bases.put(URN.createZkpgsURN("bases.edge.R_" + index), base);
      discLogOfEdgeBases.put(URN.createZkpgsURN("exponents.edge.R_" + index), x_R_ij);
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
      index++;
      x_Ri = qrGroup.createElement().getValue();
      R_i = S.modPow(x_Ri, modN);
      base = new BaseRepresentation(R_i, x_Ri, index, BASE.VERTEX);
      bases.put(URN.createZkpgsURN("bases.vertex.R_" + index), base);
      discLogOfVertexBases.put(URN.createZkpgsURN("exponents.vertex.R_" + index), x_Ri);
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
