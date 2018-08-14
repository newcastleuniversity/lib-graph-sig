package eu.prismacloud.primitives.zkpgs.signer;

import java.math.BigInteger;

import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;

/**
 * Oracle for Graph Signatures computed non-interactively with a valid ExtendedKeyPair, 
 * but without involvement of a Recipient. The GSSigningOracle determines a master
 * secret key randomly.  
 */
public class GSSigningOracle {
	private final SignerKeyPair signerKeyPair;
	private final KeyGenParameters keyGenParameters;
	private GraphEncodingParameters graphEncodingParameters;
	private final GroupElement baseS;
	private final GroupElement baseZ;
	private final BigInteger modN;


	/**
	 * Constructor for the GSSigningOracle for bare signatures without graph encoding.
	 * 
	 * @param ekp ExtendedKeyPair to be used
	 * @param keyGenParameters Parameters matching the ExtendedKeyPair
	 */
	public GSSigningOracle(SignerKeyPair skp,
			KeyGenParameters keyGenParameters) {
		this.signerKeyPair = skp;
		this.keyGenParameters = keyGenParameters;
		this.baseS = signerKeyPair.getPublicKey().getBaseS();
		this.baseZ = signerKeyPair.getPublicKey().getBaseZ();
		this.modN = signerKeyPair.getPublicKey().getModN();
	}

	/**
	 * Constructor for the GSSigningOracle preparing for signatures under a specific graph encoding.
	 * 
	 * @param ekp ExtendedKeyPair to be used
	 * @param keyGenParameters Parameters matching the ExtendedKeyPair
	 * @param graphEncodingParameters Specification of the graph encoding
	 */
	public GSSigningOracle(SignerKeyPair skp,
			KeyGenParameters keyGenParameters,
			GraphEncodingParameters graphEncodingParameters) {
		this.signerKeyPair = skp;
		this.keyGenParameters = keyGenParameters;
		this.graphEncodingParameters = graphEncodingParameters;
		this.baseS = signerKeyPair.getPublicKey().getBaseS();
		this.baseZ = signerKeyPair.getPublicKey().getBaseZ();
		this.modN = signerKeyPair.getPublicKey().getModN();
	}


	/**
	 * Creates a fresh signature with uniformly random blinding randomness,
	 * on a GroupElement Y, oblivious of the structure of Y.
	 * 
	 * @param Y GroupElement to be signed 
	 * 
	 * @return valid GSSignature 
	 */
	public GSSignature sign(GroupElement Y) {
		BigInteger v = generateBlindingV();
		GroupElement blindingS = this.baseS.modPow(v);

		GroupElement result = Y.multiply(blindingS);

		GroupElement Q = this.baseZ.multiply(result.modInverse());
		BigInteger e = generateSigningE();

		GroupElement A = computeA(Q, e);

		return new GSSignature(this.signerKeyPair.getPublicKey(), A, e, v);
	}

	/**
	 * Creates a fresh signature with uniformly random blinding randomness,
	 * on a zero message m, but without graph encoding.
	 * 
	 * @param m BigInteger message for zero's base
	 * 
	 * @return valid GSSignature 
	 */
	public GSSignature sign(BigInteger m) {
		GroupElement mEncoded = this.signerKeyPair.getPublicKey().getBaseR_0().modPow(m);

		return this.sign(mEncoded);
	}

	/**
	 * Generates the blinding randomness faithfully to the randomness combined by Recipient
	 * and signer, that is <tt>v = v' + v''</tt>.
	 *  
	 * @return BigInteger Blinding Randomness v
	 */
	public BigInteger generateBlindingV() {
		BigInteger vPrime = CryptoUtilsFacade.computeRandomNumberMinusPlus(
				this.keyGenParameters.getL_n() + this.keyGenParameters.getL_statzk());
		BigInteger vbar = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_v() - 1);
		BigInteger vPrimePrime = NumberConstants.TWO.getValue().pow(keyGenParameters.getL_v() - 1).add(vbar);
		BigInteger v = vPrime.add(vPrimePrime);
		return v;
	}

	/**
	 * Generates a prime exponent e for signing.
	 * 
	 * @return Probable Prime e in appropriate range.
	 */
	public BigInteger generateSigningE() {
		BigInteger e =
				CryptoUtilsFacade.computePrimeInRange(
						keyGenParameters.getLowerBoundE(), keyGenParameters.getUpperBoundE());
		return e;
	}

	/**
	 * Completes the signature by computing A.
	 * @param GroupElement Q prepared group element for signing
	 * @param BigInteger e prime exponent part of the signature 
	 * @return GroupElement A to complete the signature
	 */
	public GroupElement computeA(GroupElement Q, BigInteger e) {
		BigInteger pPrime = signerKeyPair.getPrivateKey().getpPrime();
		BigInteger qPrime = signerKeyPair.getPrivateKey().getqPrime();

		BigInteger d = e.modInverse(pPrime.multiply(qPrime));
		GroupElement A = Q.modPow(d);
		return A;
	}
}
