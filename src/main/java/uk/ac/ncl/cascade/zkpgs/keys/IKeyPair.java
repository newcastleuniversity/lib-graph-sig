/**
 * 
 */
package uk.ac.ncl.cascade.zkpgs.keys;

import java.io.Serializable;

import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.store.IURNGoverner;

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
