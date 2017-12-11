package eu.prismacloud.primitives.grs.utils;


import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.math.BigInteger;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test Jacobi symbol computation
 */
public class JacobiSymbolTest {
    private static final Logger log = Logger.getLogger(JacobiSymbolTest.class.getName());

//    private JacobiSymbol classUnderTest;


    @BeforeEach
    void setUp() {
        //classUnderTest = new JacobiSymbol();
    }

    @AfterEach
    void tearDown() {
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.NANOSECONDS)
    public void measureJacobiSymbol() {
        JacobiSymbol.computeJacobiSymbol(new BigInteger("3"), new BigInteger("19"));
        JacobiSymbol.computeJacobiSymbol(new BigInteger("19"), new BigInteger("27"));
        JacobiSymbol.computeJacobiSymbol(new BigInteger("15"), new BigInteger("9"));

    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.NANOSECONDS)
    public void measureJacobiSymbolBA() {
        JacobiSymbol.computeJacobiSymbolBA(new BigInteger("3"), new BigInteger("19"));
        JacobiSymbol.computeJacobiSymbolBA(new BigInteger("19"), new BigInteger("27"));
        JacobiSymbol.computeJacobiSymbolBA(new BigInteger("15"), new BigInteger("9"));
    }


    @Test
    @DisplayName("Test compute Jacobi Symbol")
    void computeJacobiSymbol() {
        log.info("@Test: computeJacobiSymbol");

        assertEquals(-1, JacobiSymbol.computeJacobiSymbolBA(new BigInteger("3"), new BigInteger("19")));

        assertEquals(1, JacobiSymbol.computeJacobiSymbolBA(new BigInteger("19"), new BigInteger("27")));

        assertEquals(0, JacobiSymbol.computeJacobiSymbolBA(new BigInteger("15"), new BigInteger("9")));
    }


    @Test
    @DisplayName("Test splitPowerRemainder")
    void splitPowerRemainder() {
        log.info("@Test: splitPowerRemainder");
//        assertNotNull();
        BigInteger sp = JacobiSymbol.splitPowerRemainder(new BigInteger("347"));
        assertEquals(new BigInteger("91"), sp);

        BigInteger sp1 = JacobiSymbol.splitPowerRemainder(new BigInteger("23297"));
        assertEquals(new BigInteger("6913"), sp1);


    }

    @Test
    @DisplayName("Test compute Jacobi symbol BA")
    void computeJacobiSymbolBA() {
        log.info("@Test: computeJacobiSymbolBA");

        assertEquals(-1, JacobiSymbol.computeJacobiSymbolBA(new BigInteger("3"), new BigInteger("19")));

        assertEquals(1, JacobiSymbol.computeJacobiSymbolBA(new BigInteger("19"), new BigInteger("27")));

        assertEquals(0, JacobiSymbol.computeJacobiSymbolBA(new BigInteger("15"), new BigInteger("9")));

    }


    public static void main(String[] args) throws RunnerException {

        Options opt = new OptionsBuilder()

                .include(JacobiSymbolTest.class.getSimpleName())

                .warmupIterations(5)

                .measurementIterations(5)

                .forks(1)

                .build();


        new Runner(opt).run();

    }

}