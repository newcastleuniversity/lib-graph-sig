package uk.ac.ncl.cascade.binding;

import uk.ac.ncl.cascade.zkpgs.graph.GSEdge;
import uk.ac.ncl.cascade.zkpgs.graph.GSGraph;
import uk.ac.ncl.cascade.zkpgs.graph.GSVertex;
import uk.ac.ncl.cascade.zkpgs.graph.GraphRepresentation;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedPublicKey;
import uk.ac.ncl.cascade.zkpgs.store.IURNGoverner;

import java.io.Serializable;

/**
 * Created by Ioannis Sfyrakis on 28/01/2022
 */
public class VCRepresentation extends GraphRepresentation implements IURNGoverner, Serializable {

	public static final String URNID = "vcrepresentation";


	protected VCRepresentation(GSGraph<GSVertex, GSEdge> gsgraph, ExtendedPublicKey epk) {
		
		super(gsgraph, epk);
	}
}
