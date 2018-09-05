/**
 * 
 */
package eu.prismacloud.primitives.zkpgs.keys;

import java.io.Serializable;

import eu.prismacloud.primitives.zkpgs.context.IContextProducer;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;

/**
 * Interface of any public key
 *
 */
public interface IPublicKey extends IContextProducer, Serializable {

	KeyGenParameters getKeyGenParameters();
	
}
