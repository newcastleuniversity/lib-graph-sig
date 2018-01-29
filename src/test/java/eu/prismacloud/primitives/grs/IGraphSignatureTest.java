package eu.prismacloud.primitives.grs;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;


public class IGraphSignatureTest extends TestCase {
    /**
         * Create the test case
         *
         * @param testName name of the test case
         */
        public IGraphSignatureTest( String testName )
        {
            super( testName );
        }

        /**
         * @return the suite of tests being tested
         */
        public static Test suite()
        {
            return new TestSuite( IGraphSignatureTest.class );
        }

        /**
         * Rigourous Test :-)
         */
        public void testApp()
        {
            assertTrue( true );
        }
}
