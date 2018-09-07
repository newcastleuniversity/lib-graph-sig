package eu.prismacloud.primitives.zkpgs.context;

import java.util.List;

/**
 * A context producer takes responsibility for enumerating public
 * data that shall be represented in an IContext proof context.
 *
 * <p>A IContextProducer is responsible to always return the same
 * context items and to maintain their order.
 */
public interface IContextProducer {

    /**
     * Returns a list of String, where each string represents a
     * public value canonically to be included in an IContext proof context.
     *
     * @return List of String, of public values for inclusion in the proof context.
     */
    List<String> computeChallengeContext();

    /**
     * Takes an existing context list as input and adds its own public values to it.
     * Each string represents a public value canonically to be included in an IContext proof context.
     *
     * @param ctxList context list
     */
    void addToChallengeContext(List<String> ctxList);
}
