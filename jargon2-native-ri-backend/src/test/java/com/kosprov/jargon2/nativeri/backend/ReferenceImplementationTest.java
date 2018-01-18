package com.kosprov.jargon2.nativeri.backend;

import com.kosprov.jargon2.spi.Jargon2Backend;
import com.kosprov.jargon2.spi.Jargon2BackendException;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static com.kosprov.jargon2.api.Jargon2.Type.*;
import static com.kosprov.jargon2.api.Jargon2.Version.V10;
import static com.kosprov.jargon2.api.Jargon2.Version.V13;
import static com.kosprov.jargon2.nativeri.backend.TestUtils.*;
import static org.junit.Assert.*;

/**
 * Test vectors from C reference implementation
 */
public class ReferenceImplementationTest {
    /**
     * Example from https://github.com/P-H-C/phc-winner-argon2/blob/master/README.md
     *
     * @throws Exception
     */
    @Test
    public void testHashFromOfficialExample() throws Exception {
        Jargon2Backend backend = new NativeRiJargon2Backend();

        byte[] password = "password".getBytes(StandardCharsets.UTF_8);
        byte[] salt = "somesalt".getBytes(StandardCharsets.UTF_8);

        String encodedHash = backend.encodedHash(
                ARGON2i,
                V13,
                65536,
                2,
                4,
                4,
                24,
                null,
                null,
                salt,
                password,
                null
        );

        assertNotNull(encodedHash);

        assertEquals("$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG", encodedHash);

        boolean matches = backend.verifyEncoded(encodedHash, 4, null, null, password, null);
        assertTrue(matches);
    }

    /**
     * Test vectors from https://github.com/P-H-C/phc-winner-argon2/blob/master/src/test.c
     *
     * @throws Exception
     */
    @Test
    public void testWithReferenceImplTestVectors() throws Exception {

        hashTest(ARGON2i, V10, 2, (int) Math.pow(2, 16), 1, 1,
                "password", "somesalt",
                "f6c4db4a54e2a370627aff3db6176b94a2a209a62c8e36152711802f7b30c694",
                "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ");

        hashTest(ARGON2i, V10, 2, (int) Math.pow(2, 8), 1, 1,
                "password", "somesalt",
                "fd4dd83d762c49bdeaf57c47bdcd0c2f1babf863fdeb490df63ede9975fccf06",
                "$argon2i$m=256,t=2,p=1$c29tZXNhbHQ$/U3YPXYsSb3q9XxHvc0MLxur+GP960kN9j7emXX8zwY");

        hashTest(ARGON2i, V10, 2, (int) Math.pow(2, 8), 2, 1,
                "password", "somesalt",
                "b6c11560a6a9d61eac706b79a2f97d68b4463aa3ad87e00c07e2b01e90c564fb",
                "$argon2i$m=256,t=2,p=2$c29tZXNhbHQ$tsEVYKap1h6scGt5ovl9aLRGOqOth+AMB+KwHpDFZPs");

        hashTest(ARGON2i, V10, 1, (int) Math.pow(2, 16), 1, 1,
                "password", "somesalt",
                "81630552b8f3b1f48cdb1992c4c678643d490b2b5eb4ff6c4b3438b5621724b2",
                "$argon2i$m=65536,t=1,p=1$c29tZXNhbHQ$gWMFUrjzsfSM2xmSxMZ4ZD1JCytetP9sSzQ4tWIXJLI");

        hashTest(ARGON2i, V10, 4, (int) Math.pow(2, 16), 1, 1,
                "password", "somesalt",
                "f212f01615e6eb5d74734dc3ef40ade2d51d052468d8c69440a3a1f2c1c2847b",
                "$argon2i$m=65536,t=4,p=1$c29tZXNhbHQ$8hLwFhXm6110c03D70Ct4tUdBSRo2MaUQKOh8sHChHs");

        hashTest(ARGON2i, V10, 2, (int) Math.pow(2, 16), 1, 1,
                "differentpassword", "somesalt",
                "e9c902074b6754531a3a0be519e5baf404b30ce69b3f01ac3bf21229960109a3",
                "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ$6ckCB0tnVFMaOgvlGeW69ASzDOabPwGsO/ISKZYBCaM");

        hashTest(ARGON2i, V10, 2, (int) Math.pow(2, 16), 1, 1,
                "password", "diffsalt",
                "79a103b90fe8aef8570cb31fc8b22259778916f8336b7bdac3892569d4f1c497",
                "$argon2i$m=65536,t=2,p=1$ZGlmZnNhbHQ$eaEDuQ/orvhXDLMfyLIiWXeJFvgza3vaw4kladTxxJc");

        hashTest(ARGON2i, V13, 2, (int) Math.pow(2, 16), 1, 1,
                "password", "somesalt",
                "c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0",
                "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA");

        hashTest(ARGON2i, V13, 2, (int) Math.pow(2, 8), 1, 1,
                "password", "somesalt",
                "89e9029f4637b295beb027056a7336c414fadd43f6b208645281cb214a56452f",
                "$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8");

        hashTest(ARGON2i, V13, 2, (int) Math.pow(2, 8), 2, 2,
                "password", "somesalt",
                "4ff5ce2769a1d7f4c8a491df09d41a9fbe90e5eb02155a13e4c01e20cd4eab61",
                "$argon2i$v=19$m=256,t=2,p=2$c29tZXNhbHQ$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E");

        hashTest(ARGON2i, V13, 1, (int) Math.pow(2, 16), 1, 1,
                "password", "somesalt",
                "d168075c4d985e13ebeae560cf8b94c3b5d8a16c51916b6f4ac2da3ac11bbecf",
                "$argon2i$v=19$m=65536,t=1,p=1$c29tZXNhbHQ$0WgHXE2YXhPr6uVgz4uUw7XYoWxRkWtvSsLaOsEbvs8");

        hashTest(ARGON2i, V13, 4, (int) Math.pow(2, 16), 1, 1,
                "password", "somesalt",
                "aaa953d58af3706ce3df1aefd4a64a84e31d7f54175231f1285259f88174ce5b",
                "$argon2i$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$qqlT1YrzcGzj3xrv1KZKhOMdf1QXUjHxKFJZ+IF0zls");

        hashTest(ARGON2i, V13, 2, (int) Math.pow(2, 16), 1, 1,
                "differentpassword", "somesalt",
                "14ae8da01afea8700c2358dcef7c5358d9021282bd88663a4562f59fb74d22ee",
                "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$FK6NoBr+qHAMI1jc73xTWNkCEoK9iGY6RWL1n7dNIu4");

        hashTest(ARGON2i, V13, 2, (int) Math.pow(2, 16), 1, 1,
                "password", "diffsalt",
                "b0357cccfbef91f3860b0dba447b2348cbefecadaf990abfe9cc40726c521271",
                "$argon2i$v=19$m=65536,t=2,p=1$ZGlmZnNhbHQ$sDV8zPvvkfOGCw26RHsjSMvv7K2vmQq/6cxAcmxSEnE");
    }

    /**
     * Test vectors from https://github.com/P-H-C/phc-winner-argon2/blob/master/src/test.c
     *
     * @throws Exception
     */
    @Test(expected = Jargon2BackendException.class)
    public void testInvalidEncodingV10() {
        verify("$argon2i$m=65536,t=2,p=1c29tZXNhbHQ$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ", 1, "password");
    }

    /**
     * Test vectors from https://github.com/P-H-C/phc-winner-argon2/blob/master/src/test.c
     *
     * @throws Exception
     */
    @Test(expected = Jargon2BackendException.class)
    public void testInvalidEncoding2V10() {
        verify("$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ", 1, "password");
    }

    /**
     * Test vectors from https://github.com/P-H-C/phc-winner-argon2/blob/master/src/test.c
     *
     * @throws Exception
     */
    @Test(expected = Jargon2BackendException.class)
    public void testSaltTooShortV10() {
        verify("$argon2i$m=65536,t=2,p=1$$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ", 1, "password");
    }

    /**
     * Test vectors from https://github.com/P-H-C/phc-winner-argon2/blob/master/src/test.c
     *
     * @throws Exception
     */
    @Test(expected = Jargon2BackendException.class)
    public void testInvalidEncodingV13() {
        verify("$argon2i$v=19$m=65536,t=2,p=1c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA", 1, "password");
    }

    /**
     * Test vectors from https://github.com/P-H-C/phc-winner-argon2/blob/master/src/test.c
     *
     * @throws Exception
     */
    @Test(expected = Jargon2BackendException.class)
    public void testInvalidEncoding2V13() {
        verify("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQwWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA", 1, "password");
    }

    /**
     * Test vectors from https://github.com/P-H-C/phc-winner-argon2/blob/master/src/test.c
     *
     * @throws Exception
     */
    @Test(expected = Jargon2BackendException.class)
    public void testSaltTooShortV13() {
        verify("$argon2i$v=19$m=65536,t=2,p=1$$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ", 1, "password");
    }

    /**
     * Test vectors from https://github.com/P-H-C/phc-winner-argon2/blob/master/src/test.c
     *
     * @throws Exception
     */
    @Test(expected = Jargon2BackendException.class)
    public void testMemoryTooLittle() {
        hash(ARGON2i, V13, 2, 1, 1, 1, "password", "diffsalt");
    }

    /**
     * Test vectors from https://github.com/P-H-C/phc-winner-argon2/blob/master/src/test.c
     *
     * @throws Exception
     */
    @Test(expected = Jargon2BackendException.class)
    public void testSaltTooShort() {
        hash(ARGON2i, V13, 2, (int) Math.pow(2, 12), 1, 1, "password", "s");
    }

    /**
     * Test vectors from https://www.ietf.org/id/draft-irtf-cfrg-argon2-03.txt
     *
     * @throws Exception
     */
    @Test
    public void testWithIetfTestVectors() throws Exception {
        byte[] password = new byte[32];
        Arrays.fill(password, (byte) 0x01);

        byte[] salt = new byte[16];
        Arrays.fill(salt, (byte) 0x02);

        byte[] secret = new byte[8];
        Arrays.fill(secret, (byte) 0x03);

        byte[] ad = new byte[12];
        Arrays.fill(ad, (byte) 0x04);

        hashTest(ARGON2d, V13, 3, 32, 4, 4, 32, password, salt, secret, ad,
                "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb");

        hashTest(ARGON2i, V13, 3, 32, 4, 4, 32, password, salt, secret, ad,
                "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8");

        hashTest(ARGON2id, V13, 3, 32, 4, 4, 32, password, salt, secret, ad,
                "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
    }
}