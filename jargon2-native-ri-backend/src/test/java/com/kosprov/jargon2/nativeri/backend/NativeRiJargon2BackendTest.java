package com.kosprov.jargon2.nativeri.backend;

import com.kosprov.jargon2.spi.Jargon2Backend;
import com.kosprov.jargon2.spi.Jargon2BackendException;
import org.junit.Test;

import javax.xml.bind.DatatypeConverter;
import java.util.Arrays;
import java.util.Random;

import static com.kosprov.jargon2.api.Jargon2.Type.ARGON2i;
import static com.kosprov.jargon2.api.Jargon2.Version.V13;
import static org.junit.Assert.*;

public class NativeRiJargon2BackendTest {
    @Test
    public void testDifferentLanesAndThreads() throws Exception {
        Jargon2Backend backend = new NativeRiJargon2Backend();

        byte[] password = "password".getBytes("UTF-8");
        byte[] salt = "somesalt".getBytes("UTF-8");

        String encodedHash = backend.encodedHash(
                ARGON2i,
                V13,
                65536,
                2,
                4,
                2,    // use only 2 threads to calculate 4 lanes
                24,
                null,
                null,
                salt,
                password,
                null
        );

        assertNotNull(encodedHash);

        assertEquals("$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG", encodedHash);

        boolean matches = backend.verifyEncoded(
                encodedHash,
                1,    // use only 1 thread to calculate 4 lanes
                null,
                null,
                password,
                null
        );

        assertTrue(matches);
    }

    @Test
    public void base64Test() throws Exception {
        NativeRiJargon2Backend backend = new NativeRiJargon2Backend();

        {
            byte[] input = "any carnal pleasure.".getBytes("UTF-8");
            char[] base64 = backend.base64encode(input);
            assertTrue(Arrays.equals("YW55IGNhcm5hbCBwbGVhc3VyZS4".toCharArray(), base64));
            byte[] decoded = backend.base64decode(new String(base64));
            assertTrue(Arrays.equals(input, decoded));
        }

        {
            byte[] input = "any carnal pleasure".getBytes("UTF-8");
            char[] base64 = backend.base64encode(input);
            assertTrue(Arrays.equals("YW55IGNhcm5hbCBwbGVhc3VyZQ".toCharArray(), base64));
            byte[] decoded = backend.base64decode(new String(base64));
            assertTrue(Arrays.equals(input, decoded));
        }

        {
            byte[] input = "any carnal pleasur".getBytes("UTF-8");
            char[] base64 = backend.base64encode(input);
            assertTrue(Arrays.equals("YW55IGNhcm5hbCBwbGVhc3Vy".toCharArray(), base64));
            byte[] decoded = backend.base64decode(new String(base64));
            assertTrue(Arrays.equals(input, decoded));
        }

        {
            byte[] input = "any carnal pleasu".getBytes("UTF-8");
            char[] base64 = backend.base64encode(input);
            assertTrue(Arrays.equals("YW55IGNhcm5hbCBwbGVhc3U".toCharArray(), base64));
            byte[] decoded = backend.base64decode(new String(base64));
            assertTrue(Arrays.equals(input, decoded));
        }

        {
            byte[] input = "any carnal pleas".getBytes("UTF-8");
            char[] base64 = backend.base64encode(input);
            assertTrue(Arrays.equals("YW55IGNhcm5hbCBwbGVhcw".toCharArray(), base64));
            byte[] decoded = backend.base64decode(new String(base64));
            assertTrue(Arrays.equals(input, decoded));
        }

        {
            byte[] input = "M".getBytes("UTF-8");
            char[] base64 = backend.base64encode(input);
            assertTrue(Arrays.equals("TQ".toCharArray(), base64));
            byte[] decoded = backend.base64decode(new String(base64));
            assertTrue(Arrays.equals(input, decoded));
        }

        {
            byte[] input = "Ma".getBytes("UTF-8");
            char[] base64 = backend.base64encode(input);
            assertTrue(Arrays.equals("TWE".toCharArray(), base64));
            byte[] decoded = backend.base64decode(new String(base64));
            assertTrue(Arrays.equals(input, decoded));
        }

        {
            byte[] input = "Man".getBytes("UTF-8");
            char[] base64 = backend.base64encode(input);
            assertTrue(Arrays.equals("TWFu".toCharArray(), base64));
            byte[] decoded = backend.base64decode(new String(base64));
            assertTrue(Arrays.equals(input, decoded));
        }

        {
            for (int i = -2; i <= 2; i++) {
                byte[] input = new byte[1024 * 1024 + i];
                new Random().nextBytes(input);
                char[] base64 = backend.base64encode(input);
                String standard = DatatypeConverter.printBase64Binary(input);
                while (standard.charAt(standard.length() - 1) == '=') {
                    standard = standard.substring(0, standard.length() - 1);
                }
                assertTrue(Arrays.equals(standard.toCharArray(), base64));
                byte[] decoded = backend.base64decode(new String(base64));
                assertTrue(Arrays.equals(input, decoded));
            }
        }
    }

    @Test(expected = Jargon2BackendException.class)
    public void base64WrongCharTest() {
        NativeRiJargon2Backend backend = new NativeRiJargon2Backend();
        backend.base64decode("YW55IGNhcm*hbCBwbGVhcw");
    }

    @Test(expected = Jargon2BackendException.class)
    public void base64WrongChar2Test() {
        NativeRiJargon2Backend backend = new NativeRiJargon2Backend();
        backend.base64decode("Φούμπαρ");
    }

    @Test(expected = Jargon2BackendException.class)
    public void base64WrongNumber1Test() {
        NativeRiJargon2Backend backend = new NativeRiJargon2Backend();
        backend.base64decode("A");
    }

    @Test(expected = Jargon2BackendException.class)
    public void base64WrongNumber2Test() {
        NativeRiJargon2Backend backend = new NativeRiJargon2Backend();
        backend.base64decode("AAAAA");
    }

    @Test(expected = Jargon2BackendException.class)
    public void base64WrongNumber3Test() {
        NativeRiJargon2Backend backend = new NativeRiJargon2Backend();
        backend.base64decode("AAAAAAAAA");
    }

    @Test
    public void splitTest() throws Exception {
        NativeRiJargon2Backend backend = new NativeRiJargon2Backend();

        {
            String str = "aaa@bbb@ccc";
            String[] tokens = backend.split(str, '@', 3);
            String[] expectedTokens = { "aaa", "bbb", "ccc" };
            assertTrue(Arrays.equals(tokens, expectedTokens));
        }

        {
            String str = "@aaa@bbb@ccc";
            String[] tokens = backend.split(str, '@', 3);
            String[] expectedTokens = { "aaa", "bbb", "ccc" };
            assertTrue(Arrays.equals(tokens, expectedTokens));
        }

        {
            String str = "@aaa@bbb@ccc@";
            String[] tokens = backend.split(str, '@', 3);
            String[] expectedTokens = { "aaa", "bbb", "ccc" };
            assertTrue(Arrays.equals(tokens, expectedTokens));
        }

        {
            String str = "@@aaa@@bbb@@ccc@@";
            String[] tokens = backend.split(str, '@', 3);
            String[] expectedTokens = { "aaa", "bbb", "ccc" };
            assertTrue(Arrays.equals(tokens, expectedTokens));
        }

        {
            String str = "";
            String[] tokens = backend.split(str, '@', 3);
            String[] expectedTokens = {};
            assertTrue(Arrays.equals(tokens, expectedTokens));
        }

        {
            String str = "@aaa@bbb@ccc@ddd";
            String[] tokens = backend.split(str, '@', 3);
            String[] expectedTokens = { "aaa", "bbb", "ccc" };
            assertTrue(Arrays.equals(tokens, expectedTokens));
        }
    }
}