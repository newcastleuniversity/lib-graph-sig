package eu.prismacloud.primitives.zkpgs.keys;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.encoding.GeoLocationGraphEncoding;
import eu.prismacloud.primitives.zkpgs.encoding.IGraphEncoding;
import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.URN;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

/**
 * Class representing the extended key pair
 */
public final class ExtendedKeyPair implements IKeyPair, IExtendedKeyInfo, Serializable {
    /**
     *
     */
    private static final long serialVersionUID = -293401766259515133L;
	/* TODO make the keypair defensive and secure in that it is either completely immutable
	or only returns clones */

    public static final String URNID = "extendedkeypair";


    private final SignerPublicKey publicKey;
    private final SignerPrivateKey privateKey;
    private final GraphEncodingParameters graphEncodingParameters;
    private final KeyGenParameters keyGenParameters;
    private final GroupElement baseS;
    private final SignerKeyPair signerKeyPair;
    private final Map<URN, BigInteger> discLogOfBases;
    private ExtendedPublicKey extendedPublicKey;
    private ExtendedPrivateKey extendedPrivateKey;
    private Map<URN, BaseRepresentation> baseRepresentationMap;
    private IGraphEncoding graphEncoding;

    /**
     * Instantiates a new Extended key pair for a default case of a
     * geo-location graph encoding
     *
     * @param signerKeyPair           the signer key pair
     * @param graphEncodingParameters the graph encoding parameters
     * @param keyGenParameters        the key gen parameters
     */
    public ExtendedKeyPair(
            final SignerKeyPair signerKeyPair,
            final GraphEncodingParameters graphEncodingParameters,
            final KeyGenParameters keyGenParameters) {

        this.signerKeyPair = signerKeyPair;
        this.publicKey = signerKeyPair.getPublicKey();
        this.privateKey = signerKeyPair.getPrivateKey();
        this.graphEncoding =
                new GeoLocationGraphEncoding(
                        graphEncodingParameters);
        this.graphEncodingParameters = graphEncodingParameters;
        this.keyGenParameters = keyGenParameters;
        this.baseS = signerKeyPair.getPublicKey().getBaseS();
        this.baseRepresentationMap = new HashMap<URN, BaseRepresentation>();
        this.discLogOfBases = new HashMap<URN, BigInteger>();
    }

    /**
     * Instantiates a new Extended key pair for a default case of a
     * geo-location graph encoding
     *
     * @param signerKeyPair           the signer key pair
     * @param encoding                the encoding of the graph
     * @param graphEncodingParameters the graph encoding parameters
     * @param keyGenParameters        the key gen parameters
     */
    public ExtendedKeyPair(
            final SignerKeyPair signerKeyPair,
            final IGraphEncoding encoding,
            final GraphEncodingParameters graphEncodingParameters,
            final KeyGenParameters keyGenParameters) {

        this.signerKeyPair = signerKeyPair;
        this.publicKey = signerKeyPair.getPublicKey();
        this.privateKey = signerKeyPair.getPrivateKey();
        this.graphEncoding = encoding;
        this.graphEncodingParameters = graphEncodingParameters;
        this.keyGenParameters = keyGenParameters;
        this.baseS = signerKeyPair.getPublicKey().getBaseS();
        this.baseRepresentationMap = new HashMap<URN, BaseRepresentation>();
        this.discLogOfBases = new HashMap<URN, BigInteger>();
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
     * Create extended key pair.
     */
    public void createExtendedKeyPair() {
        this.extendedPublicKey =
                new ExtendedPublicKey(
                        signerKeyPair.getPublicKey(),
                        baseRepresentationMap,
                        graphEncoding,
                        graphEncodingParameters);

        this.extendedPrivateKey = new ExtendedPrivateKey(signerKeyPair.getPrivateKey(), discLogOfBases);
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
    @Override
    public SignerPublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Gets private key.
     *
     * @return the private key
     */
    @Override
    public SignerPrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * Gets graph encoding.
     *
     * @return the graph encoding
     */
    public IGraphEncoding getGraphEncoding() {
        return this.graphEncoding;
    }

    /**
     * Certify prime representatives.
     */
    public void certifyPrimeRepresentatives() {
        // TODO Certification needs to be reimplemented
        //		Group qrGroup = publicKey.getQRGroup();
        //		BigInteger x_R_V = qrGroup.createRandomElement().getValue();

        //GroupElement R_V = baseS.modPow(x_R_V);

        //BaseRepresentation baseV = new BaseRepresentation(R_V, 0, BASE.VERTEX);

        //BigInteger x_R_L = qrGroup.createRandomElement().getValue();

        //GroupElement R_L = baseS.modPow(x_R_L);

        //BaseRepresentation baseL = new BaseRepresentation(R_L, 0, BASE.VERTEX);

        //graphEncoding.certify(getVertexRepresentatives(), baseV, getLabelRepresentatives(), baseL);
    }

    /**
     * Generate edge baseRepresentationMap.
     *
     * @param S the quadratic group generator S
     */
    public void generateEdgeBases(final GroupElement S) {
        BigInteger x_R_ij;
        GroupElement R_ij;

        for (int j = 0; j < graphEncodingParameters.getL_E(); j++) {
            x_R_ij =
                    CryptoUtilsFacade.computeRandomNumber(KeyGenParameters.getKeyGenParameters().getL_n());
            R_ij = S.modPow(x_R_ij);

            /* The base representation receives as global index the current
             * length of the overall base representation map plus 1,
             * making an index counting from 1;
             */
            int index = baseRepresentationMap.size() + 1;
            BaseRepresentation base = new BaseRepresentation(R_ij, index, BASE.EDGE);

            baseRepresentationMap.put(
                    URNType.buildURN(URNType.RE, this.getClass(), index), base);
            discLogOfBases.put(URNType.buildURN(URNType.DLRE, this.getClass(), index), x_R_ij);
        }
    }

    /**
     * Generate bases.
     */
    public void generateBases() {
        generateVertexBases(baseS);
        generateEdgeBases(baseS);
    }


    // TODO METHOD FAULTY: Does not generate the right bases
    // Z etc. should be part of the SignerKeyPair, not the ExtendedKeyPair
    //	private void generateGroupBases(final GroupElement baseS) {
    //
    //		x_RZ = CryptoUtilsFacade.computeRandomNumber(KeyGenParameters.getKeyGenParameters().getL_n());
    //		R_Z = baseS.modPow(x_RZ);
    //
    //		discLogOfBases.put(URN.createZkpgsURN("discretelogs.base.R_Z"), x_RZ);
    //
    //		x_RZ = CryptoUtilsFacade.computeRandomNumber(KeyGenParameters.getKeyGenParameters().getL_n());
    //		R_Z = baseS.modPow(x_RZ);
    //
    //		discLogOfBases.put(URN.createZkpgsURN("discretelogs.base.R_Z"), x_RZ);
    //	}


    /**
     * Generates a map of a base representation drawn uniformly at random from the signer's
     * setup group. The discrete logarithms of the bases with respect to the main base S
     * are stored for the signer's extended private key.
     *
     * @param S the quadratic group generator S
     * @complexity The method is computationally intensive as it is computing l_V modular exponentiations
     * in the signer's group.
     * @post The vertex bases are stored in the keypair's baseRepresentationMap.
     * The corresponding discrete logarithms are stored in DiscLogOfBases.
     */
    public void generateVertexBases(final GroupElement S) {
        BigInteger x_Ri;
        GroupElement R_i;

        for (int i = 0; i < graphEncodingParameters.getL_V(); i++) {

            x_Ri = CryptoUtilsFacade.computeRandomNumber(KeyGenParameters.getKeyGenParameters().getL_n());
            R_i = S.modPow(x_Ri);

            /* The base representation receives as global index the current
             * length of the overall base representation map plus 1,
             * making an index counting from 1;
             */
            int index = baseRepresentationMap.size() + 1;

            BaseRepresentation base = new BaseRepresentation(R_i, index, BASE.VERTEX);
            baseRepresentationMap.put(URNType.buildURN(URNType.RV, this.getClass(), index), base);

            discLogOfBases.put(URNType.buildURN(URNType.DLRV, this.getClass(), index), x_Ri);
        }
    }

    /**
     * Gets vertex representatives.
     *
     * @return the vertex representatives
     */
    @Override
    public Map<URN, BigInteger> getVertexRepresentatives() {
        return this.graphEncoding.getVertexRepresentatives();
    }

    /**
     * Gets label representatives.
     *
     * @return the label representatives
     */
    @Override
    public Map<URN, BigInteger> getLabelRepresentatives() {
        return this.graphEncoding.getLabelRepresentatives();
    }

    @Override
    public KeyGenParameters getKeyGenParameters() {
        return this.keyGenParameters;
    }

    @Override
    public SignerKeyPair getBaseKeyPair() {
        return this.signerKeyPair;
    }

    @Override
    public GraphEncodingParameters getGraphEncodingParameters() {
        return graphEncodingParameters;
    }


    /**
     * Setups a new graph encoding.
     */
    @Override
    public void setupEncoding() throws EncodingException {
        this.graphEncoding.setupEncoding();
    }

    @Override
    public BigInteger getVertexRepresentative(String id) {
        return graphEncoding.getVertexRepresentative(id);
    }

    @Override
    public BigInteger getVertexLabelRepresentative(String label) {
        return graphEncoding.getVertexLabelRepresentative(label);
    }

    @Override
    public BigInteger getEdgeLabelRepresentative(String label) {
        return graphEncoding.getEdgeLabelRepresentative(label);
    }

    @Override
    public IGraphEncoding getEncoding() {
        return this.graphEncoding;
    }
}
