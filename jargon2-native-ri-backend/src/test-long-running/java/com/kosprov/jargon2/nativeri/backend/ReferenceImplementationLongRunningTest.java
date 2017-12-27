package com.kosprov.jargon2.nativeri.backend;

import org.junit.Test;

import static com.kosprov.jargon2.api.Jargon2.Type.ARGON2i;
import static com.kosprov.jargon2.api.Jargon2.Version.V10;
import static com.kosprov.jargon2.api.Jargon2.Version.V13;
import static com.kosprov.jargon2.nativeri.backend.TestUtils.hashTest;

/**
 * Test vectors from C reference implementation
 */
public class ReferenceImplementationLongRunningTest {

    /**
     * Large RAM test vectors from https://github.com/P-H-C/phc-winner-argon2/blob/master/src/test.c
     *
     * @throws Exception
     */
    @Test
    public void testWithReferenceImplTestVectorsLongRunning() throws Exception {

        hashTest(ARGON2i, V10, 2, (int) Math.pow(2, 20), 1, 1,
                "password", "somesalt",
                "9690ec55d28d3ed32562f2e73ea62b02b018757643a2ae6e79528459de8106e9",
                "$argon2i$m=1048576,t=2,p=1$c29tZXNhbHQ$lpDsVdKNPtMlYvLnPqYrArAYdXZDoq5ueVKEWd6BBuk");

        hashTest(ARGON2i, V10, 2, (int) Math.pow(2, 18), 1, 1,
                "password", "somesalt",
                "3e689aaa3d28a77cf2bc72a51ac53166761751182f1ee292e3f677a7da4c2467",
                "$argon2i$m=262144,t=2,p=1$c29tZXNhbHQ$Pmiaqj0op3zyvHKlGsUxZnYXURgvHuKS4/Z3p9pMJGc");

        hashTest(ARGON2i, V13, 2, (int) Math.pow(2, 20), 1, 1,
                "password", "somesalt",
                "d1587aca0922c3b5d6a83edab31bee3c4ebaef342ed6127a55d19b2351ad1f41",
                "$argon2i$v=19$m=1048576,t=2,p=1$c29tZXNhbHQ$0Vh6ygkiw7XWqD7asxvuPE667zQu1hJ6VdGbI1GtH0E");

        hashTest(ARGON2i, V13, 2, (int) Math.pow(2, 18), 1, 1,
                "password", "somesalt",
                "296dbae80b807cdceaad44ae741b506f14db0959267b183b118f9b24229bc7cb",
                "$argon2i$v=19$m=262144,t=2,p=1$c29tZXNhbHQ$KW266AuAfNzqrUSudBtQbxTbCVkmexg7EY+bJCKbx8s");

    }
}