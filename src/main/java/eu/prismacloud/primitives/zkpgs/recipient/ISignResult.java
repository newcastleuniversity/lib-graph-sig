package eu.prismacloud.primitives.zkpgs.recipient;

import eu.prismacloud.primitives.zkpgs.signature.GSGraphSignature;

public interface ISignResult {

  GSGraphSignature getGraphSignature();
}
