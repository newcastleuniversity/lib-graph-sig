/**
 * 
 */
package eu.prismacloud.primitives.zkpgs.keys;

import java.io.Serializable;

import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.IURNGoverner;

/**
 * @author ntg8
 *
 */
public interface IKeyPair extends Serializable, IURNGoverner {

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
