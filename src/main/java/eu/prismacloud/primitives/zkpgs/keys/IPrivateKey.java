/**
 * 
 */
package eu.prismacloud.primitives.zkpgs.keys;

import java.io.Serializable;

import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;

/**
 * @author ntg8
 *
 */
public interface IPrivateKey extends Serializable {

	KeyGenParameters getKeyGenParameters();
	
}
