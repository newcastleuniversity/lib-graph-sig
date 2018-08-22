/**
 * 
 */
package eu.prismacloud.primitives.zkpgs.keys;

import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;

/**
 * @author ntg8
 *
 */
public interface IKeyPair {

	IPrivateKey getPrivateKey();
	IPublicKey getPublicKey();
	
	/**
	 * Returns the underlying base key pair, for example, an ExtendedKeyPair will return the SignerKeyPair.
	 * If a key pair is already the base key pair, the convention is that it will return itself.
	 *  
	 * @return Underlying base key pair.
	 */
	IKeyPair getBaseKeyPair();
	
	KeyGenParameters getKeyGenParameters();
	
}
