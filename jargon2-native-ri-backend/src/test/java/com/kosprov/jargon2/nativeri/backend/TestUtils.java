package com.kosprov.jargon2.nativeri.backend;

import com.kosprov.jargon2.spi.Jargon2Backend;
import org.apache.commons.codec.binary.Hex;

import static com.kosprov.jargon2.api.Jargon2.Type;
import static com.kosprov.jargon2.api.Jargon2.Version;
import static org.junit.Assert.*;

class TestUtils {

    static void hashTest(Type type, Version version, int timeCost, int memoryCost, int lanes, int threads, int hashLength, byte[] password, byte[] salt, byte[] secret, byte[] ad, String rawHashHex) {
        Jargon2Backend backend = new NativeRiJargon2Backend();

        byte[] calculatedRawHashBytes = backend.rawHash(type, version, memoryCost, timeCost, lanes, threads, hashLength, secret, ad, salt, password, null);
        String calculatedRawHashHex = Hex.encodeHexString(calculatedRawHashBytes);
        assertTrue(rawHashHex.equalsIgnoreCase(calculatedRawHashHex));
    }

    static void hashTest(Type type, Version version, int timeCost, int memoryCost, int lanes, int threads, String password, String salt, String rawHashHex, String encodedHash) {
        Jargon2Backend backend = new NativeRiJargon2Backend();

        byte[] saltBytes = salt.getBytes();
        byte[] passwordBytes = password.getBytes();
        String calculatedEncodedHash = backend.encodedHash(type, version, memoryCost, timeCost, lanes, threads, 32, null, null, saltBytes, passwordBytes, null);
        assertEquals(encodedHash, calculatedEncodedHash);

        boolean encodedMatched = backend.verifyEncoded(encodedHash, threads, null, null, passwordBytes, null);
        assertTrue(encodedMatched);

        byte[] calculatedRawHashBytes = backend.rawHash(type, version, memoryCost, timeCost, lanes, threads, 32, null, null, saltBytes, passwordBytes, null);
        String calculatedRawHashHex = Hex.encodeHexString(calculatedRawHashBytes);
        assertTrue(rawHashHex.equalsIgnoreCase(calculatedRawHashHex));

        boolean rawMatched = backend.verifyRaw(type, version, memoryCost, timeCost, lanes, threads, calculatedRawHashBytes, null, null, saltBytes, passwordBytes, null);
        assertTrue(rawMatched);
    }

    static void verify(String encodedHash, int threads, String password) {
        Jargon2Backend backend = new NativeRiJargon2Backend();

        boolean matches = backend.verifyEncoded(encodedHash, threads, null, null, password.getBytes(), null);
        assertTrue(matches);
    }

    static void hash(Type type, Version version, int timeCost, int memoryCost, int lanes, int threads, String password, String salt) {
        Jargon2Backend backend = new NativeRiJargon2Backend();

        byte[] hash = backend.rawHash(type, version, memoryCost, timeCost, lanes, threads, 32, null, null, salt.getBytes(), password.getBytes(), null);
        assertNotNull(hash);
        assertTrue(hash.length == 32);
    }
}
