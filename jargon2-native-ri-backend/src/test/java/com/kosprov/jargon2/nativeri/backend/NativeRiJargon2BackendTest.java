package com.kosprov.jargon2.nativeri.backend;

import com.kosprov.jargon2.spi.Jargon2BackendException;
import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;

import static com.kosprov.jargon2.api.Jargon2.Type;
import static com.kosprov.jargon2.api.Jargon2.Type.ARGON2i;
import static com.kosprov.jargon2.api.Jargon2.Version;
import static com.kosprov.jargon2.api.Jargon2.Version.V13;
import static org.junit.Assert.*;

public class NativeRiJargon2BackendTest {

    private NativeRiJargon2Backend backend = new NativeRiJargon2Backend();

    private Type type = ARGON2i;
    private Version version = V13;
    private int memoryCost = 65536;
    private int timeCost = 2;
    private int lanes = 4;
    private int threads = 2;
    private int hashLength = 24;
    private byte[] salt = "somesalt".getBytes();
    private byte[] password = "password".getBytes();

    @Test
    public void testDifferentLanesAndThreads() throws Exception {
        String encodedHash = backend.encodedHash(
                type,
                version,
                memoryCost,
                timeCost,
                lanes,
                threads,    // use only 2 threads to calculate 4 lanes
                hashLength,
                null,
                null,
                salt,
                password,
                null
        );

        assertNotNull(encodedHash);

        assertEquals("$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG", encodedHash);

        {
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

        {
            boolean matches = backend.verifyEncoded(
                    encodedHash,
                    lanes + 1,    // use more threads than lanes
                    null,
                    null,
                    password,
                    null
            );

            assertTrue(matches);
        }

        {
            boolean matches = backend.verifyEncoded(
                    encodedHash,
                    -1,    // set threads to the number of lanes
                    null,
                    null,
                    password,
                    null
            );

            assertTrue(matches);
        }
    }

    @Test(expected = Jargon2BackendException.class)
    public void noEncodedHashTest() {
        backend.verifyEncoded(null, -1, null, null, password, null);
    }

    @Test(expected = Jargon2BackendException.class)
    public void emptyEncodedHashTest() {
        backend.verifyEncoded("", -1, null, null, password, null);
    }

    @Test(expected = Jargon2BackendException.class)
    public void noTokensEncodedHashTest() {
        backend.verifyEncoded("abcd", -1, null, null, password, null);
    }

    @Test(expected = Jargon2BackendException.class)
    public void wrongTokensEncodedHashTest() {
        backend.verifyEncoded("$abc$def", -1, null, null, password, null);
    }

    @Test(expected = Jargon2BackendException.class)
    public void wrongTypeEncodedHashTest() {
        backend.verifyEncoded("$xxx$xxx$xxx$xxx$xxx", -1, null, null, password, null);
    }

    @Test(expected = Jargon2BackendException.class)
    public void wrongVersionEncodedHashTest() {
        backend.verifyEncoded("$argon2i$xxx$xxx$xxx$xxx", -1, null, null, password, null);
    }

    @Test(expected = Jargon2BackendException.class)
    public void wrongVersionLengthEncodedHashTest() {
        backend.verifyEncoded("$argon2i$v=1$xxx$xxx$xxx", -1, null, null, password, null);
    }

    @Test(expected = Jargon2BackendException.class)
    public void wrongOptionsEncodedHashTest() {
        backend.verifyEncoded("$argon2i$v=19$xxx$xxx$xxx", -1, null, null, password, null);
    }

    @Test(expected = Jargon2BackendException.class)
    public void tooFewOptionsEncodedHashTest() {
        backend.verifyEncoded("$argon2i$v=19$a=1,b=2$xxx$xxx", -1, null, null, password, null);
    }

    @Test(expected = Jargon2BackendException.class)
    public void tooManyOptionsEncodedHashTest() {
        backend.verifyEncoded("$argon2i$v=19$a=1,b=2,c=3,d=4$xxx$xxx", -1, null, null, password, null);
    }

    @Test(expected = Jargon2BackendException.class)
    public void wrongMemoryCostEncodedHashTest() {
        backend.verifyEncoded("$argon2i$v=19$a=1,b=2,c=3$xxx$xxx", -1, null, null, password, null);
    }

    @Test(expected = Jargon2BackendException.class)
    public void wrongMemoryCostNumEncodedHashTest() {
        backend.verifyEncoded("$argon2i$v=19$m=xxx,b=2,c=3$xxx$xxx", -1, null, null, password, null);
    }

    @Test(expected = Jargon2BackendException.class)
    public void wrongTimeCostEncodedHashTest() {
        backend.verifyEncoded("$argon2i$v=19$m=65536,b=2,c=3$xxx$xxx", -1, null, null, password, null);
    }

    @Test(expected = Jargon2BackendException.class)
    public void wrongTimeCostNumEncodedHashTest() {
        backend.verifyEncoded("$argon2i$v=19$m=65536,t=xxx,c=3$xxx$xxx", -1, null, null, password, null);
    }

    @Test(expected = Jargon2BackendException.class)
    public void wrongParallelismEncodedHashTest() {
        backend.verifyEncoded("$argon2i$v=19$m=65536,t=2,c=3$xxx$xxx", -1, null, null, password, null);
    }

    @Test(expected = Jargon2BackendException.class)
    public void wrongParallelismNumEncodedHashTest() {
        backend.verifyEncoded("$argon2i$v=19$m=65536,t=2,p=xxx$xxx$xxx", -1, null, null, password, null);
    }

    @Test(expected = Jargon2BackendException.class)
    public void wrongSaltBase64EncodedHashTest() {
        backend.verifyEncoded("$argon2i$v=19$m=65536,t=2,p=4$xxx$xxx", -1, null, null, password, null);
    }

    @Test(expected = Jargon2BackendException.class)
    public void wrongOutputBase64EncodedHashTest() {
        backend.verifyEncoded("$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$xxx", -1, null, null, password, null);
    }

    @Test(expected = Jargon2BackendException.class)
    public void noTypeTest() {
        backend.encodedHash(
                null,
                version,
                memoryCost,
                timeCost,
                lanes,
                threads,
                hashLength,
                null,
                null,
                salt,
                password,
                null
        );
    }

    @Test(expected = Jargon2BackendException.class)
    public void noVersionTest() {
        backend.encodedHash(
                type,
                null,
                memoryCost,
                timeCost,
                lanes,
                threads,
                hashLength,
                null,
                null,
                salt,
                password,
                null
        );
    }

    @Test(expected = Jargon2BackendException.class)
    public void wrongHashLengthTest() {
        backend.encodedHash(
                type,
                version,
                memoryCost,
                timeCost,
                lanes,
                threads,
                1, // one byte output
                null,
                null,
                salt,
                password,
                null
        );
    }

    @Test(expected = Jargon2BackendException.class)
    public void noSaltTest() {
        backend.encodedHash(
                type,
                version,
                memoryCost,
                timeCost,
                lanes,
                threads,
                hashLength,
                null,
                null,
                null,
                password,
                null
        );
    }

    @Test(expected = Jargon2BackendException.class)
    public void wrongSaltLengthTest() {
        backend.encodedHash(
                type,
                version,
                memoryCost,
                timeCost,
                lanes,
                threads,
                hashLength,
                null,
                null,
                new byte[7],
                password,
                null
        );
    }

    @Test(expected = Jargon2BackendException.class)
    public void noPasswordTest() {
        backend.encodedHash(
                type,
                version,
                memoryCost,
                timeCost,
                lanes,
                threads,
                hashLength,
                null,
                null,
                salt,
                null,
                null
        );
    }

    @Test(expected = Jargon2BackendException.class)
    public void wrongPasswordLengthTest() {
        backend.encodedHash(
                type,
                version,
                memoryCost,
                timeCost,
                lanes,
                threads,
                hashLength,
                null,
                null,
                salt,
                new byte[0],
                null
        );
    }

    @Test(expected = Jargon2BackendException.class)
    public void wrongLanesTest() {
        backend.encodedHash(
                type,
                version,
                memoryCost,
                timeCost,
                0,
                threads,
                hashLength,
                null,
                null,
                salt,
                password,
                null
        );
    }

    @Test(expected = Jargon2BackendException.class)
    public void wrongThreadsTest() {
        backend.encodedHash(
                type,
                version,
                memoryCost,
                timeCost,
                lanes,
                0,
                hashLength,
                null,
                null,
                salt,
                password,
                null
        );
    }

    @Test(expected = Jargon2BackendException.class)
    public void wrongMemoryCostTest() {
        backend.encodedHash(
                type,
                version,
                7,
                timeCost,
                lanes,
                threads,
                hashLength,
                null,
                null,
                salt,
                password,
                null
        );
    }

    @Test(expected = Jargon2BackendException.class)
    public void wrongMemoryCostGivenLanesTest() {
        backend.encodedHash(
                type,
                version,
                8 * lanes - 1,
                timeCost,
                lanes,
                threads,
                hashLength,
                null,
                null,
                salt,
                password,
                null
        );
    }

    @Test(expected = Jargon2BackendException.class)
    public void wrongTimeCostTest() {
        backend.encodedHash(
                type,
                version,
                memoryCost,
                0,
                lanes,
                threads,
                hashLength,
                null,
                null,
                salt,
                password,
                null
        );
    }

    @Test
    public void base64Test() throws Exception {
        {
            byte[] input = "any carnal pleasure.".getBytes(StandardCharsets.UTF_8);
            char[] base64 = backend.base64encode(input);
            assertTrue(Arrays.equals("YW55IGNhcm5hbCBwbGVhc3VyZS4".toCharArray(), base64));
            byte[] decoded = backend.base64decode(new String(base64));
            assertTrue(Arrays.equals(input, decoded));
        }

        {
            byte[] input = "any carnal pleasure".getBytes(StandardCharsets.UTF_8);
            char[] base64 = backend.base64encode(input);
            assertTrue(Arrays.equals("YW55IGNhcm5hbCBwbGVhc3VyZQ".toCharArray(), base64));
            byte[] decoded = backend.base64decode(new String(base64));
            assertTrue(Arrays.equals(input, decoded));
        }

        {
            byte[] input = "any carnal pleasur".getBytes(StandardCharsets.UTF_8);
            char[] base64 = backend.base64encode(input);
            assertTrue(Arrays.equals("YW55IGNhcm5hbCBwbGVhc3Vy".toCharArray(), base64));
            byte[] decoded = backend.base64decode(new String(base64));
            assertTrue(Arrays.equals(input, decoded));
        }

        {
            byte[] input = "any carnal pleasu".getBytes(StandardCharsets.UTF_8);
            char[] base64 = backend.base64encode(input);
            assertTrue(Arrays.equals("YW55IGNhcm5hbCBwbGVhc3U".toCharArray(), base64));
            byte[] decoded = backend.base64decode(new String(base64));
            assertTrue(Arrays.equals(input, decoded));
        }

        {
            byte[] input = "any carnal pleas".getBytes(StandardCharsets.UTF_8);
            char[] base64 = backend.base64encode(input);
            assertTrue(Arrays.equals("YW55IGNhcm5hbCBwbGVhcw".toCharArray(), base64));
            byte[] decoded = backend.base64decode(new String(base64));
            assertTrue(Arrays.equals(input, decoded));
        }

        {
            byte[] input = "M".getBytes(StandardCharsets.UTF_8);
            char[] base64 = backend.base64encode(input);
            assertTrue(Arrays.equals("TQ".toCharArray(), base64));
            byte[] decoded = backend.base64decode(new String(base64));
            assertTrue(Arrays.equals(input, decoded));
        }

        {
            byte[] input = "Ma".getBytes(StandardCharsets.UTF_8);
            char[] base64 = backend.base64encode(input);
            assertTrue(Arrays.equals("TWE".toCharArray(), base64));
            byte[] decoded = backend.base64decode(new String(base64));
            assertTrue(Arrays.equals(input, decoded));
        }

        {
            byte[] input = "Man".getBytes(StandardCharsets.UTF_8);
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
                String standard = Base64.encodeBase64String(input);
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
        backend.base64decode("YW55IGNhcm*hbCBwbGVhcw");
    }

    @Test(expected = Jargon2BackendException.class)
    public void base64WrongChar2Test() {
        backend.base64decode("Φούμπαρ");
    }

    @Test(expected = Jargon2BackendException.class)
    public void base64WrongNumber1Test() {
        backend.base64decode("A");
    }

    @Test(expected = Jargon2BackendException.class)
    public void base64WrongNumber2Test() {
        backend.base64decode("AAAAA");
    }

    @Test(expected = Jargon2BackendException.class)
    public void base64WrongNumber3Test() {
        backend.base64decode("AAAAAAAAA");
    }

    @Test
    public void splitTest() {
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