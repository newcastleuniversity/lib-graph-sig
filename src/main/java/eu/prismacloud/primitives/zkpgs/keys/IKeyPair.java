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
	KeyGenParameters getKeyGenParameters();
	
}