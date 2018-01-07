package com.kosprov.jargon2.nativeri.backend;

import argon2.Argon2Library;
import argon2.Argon2_Context;
import com.kosprov.jargon2.spi.Jargon2Backend;
import com.kosprov.jargon2.spi.Jargon2BackendException;
import com.sun.jna.Memory;

import java.util.Arrays;
import java.util.Map;

import static argon2.Argon2Library.*;
import static argon2.Argon2Library.Argon2_ErrorCodes.ARGON2_OK;
import static argon2.Argon2Library.Argon2_type.*;
import static argon2.Argon2Library.Argon2_version.ARGON2_VERSION_10;
import static argon2.Argon2Library.Argon2_version.ARGON2_VERSION_13;
import static com.kosprov.jargon2.api.Jargon2.Type;
import static com.kosprov.jargon2.api.Jargon2.Version;

public class NativeRiJargon2Backend implements Jargon2Backend {

    @Override
    public byte[] rawHash(Type type, Version version, int memoryCost, int timeCost, int lanes, int threads, int hashLength, byte[] secret, byte[] ad, byte[] salt, byte[] password, Map<String, Object> options) {

        if (hashLength < ARGON2_MIN_OUTLEN) {
            throw new Jargon2BackendException("Hash length must be greater or equal to " + ARGON2_MIN_OUTLEN);
        }

        if (salt == null || salt.length < ARGON2_MIN_SALT_LENGTH) {
            throw new Jargon2BackendException("Salt must not be null and its length must be greater or equal to " + ARGON2_MIN_SALT_LENGTH);
        }

        if (password == null || password.length == 0) {
            throw new Jargon2BackendException("Password must not be null or empty");
        }

        if (lanes < ARGON2_MIN_LANES) {
            throw new Jargon2BackendException("Lanes must be greater or equal to " + ARGON2_MIN_LANES);
        }

        if (lanes > ARGON2_MAX_LANES) {
            throw new Jargon2BackendException("Lanes must be less or equal to " + ARGON2_MAX_LANES);
        }

        if (threads < ARGON2_MIN_THREADS) {
            throw new Jargon2BackendException("Threads must be greater or equal to " + ARGON2_MIN_THREADS);
        }

        if (threads > ARGON2_MAX_THREADS) {
            throw new Jargon2BackendException("Threads must be less or equal to " + ARGON2_MAX_THREADS);
        }

        if (threads > lanes) {
            threads = lanes;
        }

        if (memoryCost < ARGON2_MIN_MEMORY) {
            throw new Jargon2BackendException("Memory cost must be greater or equal to " + ARGON2_MIN_MEMORY);
        }

        if (memoryCost < 2 * ARGON2_SYNC_POINTS * lanes) {
            throw new Jargon2BackendException("Memory cost must be greater or equal to " + (2 * ARGON2_SYNC_POINTS) + " * lanes");
        }

        if (timeCost < ARGON2_MIN_TIME) {
            throw new Jargon2BackendException("Time cost must be greater or equal to " + ARGON2_MIN_TIME);
        }


        DisposableMemory passwordMemory = null;
        DisposableMemory saltMemory = null;
        DisposableMemory secretMemory = null;
        DisposableMemory adMemory = null;
        DisposableMemory outputMemory = null;

        try {
            passwordMemory = copyToMemory(password);
            saltMemory = copyToMemory(salt);
            secretMemory = copyToMemory(secret);
            adMemory = copyToMemory(ad);
            outputMemory = createMemory(hashLength);

            Argon2_Context ctx = new Argon2_Context.ByReference();
            ctx.out = outputMemory;
            ctx.outlen = hashLength;
            ctx.pwd = passwordMemory;
            ctx.pwdlen = password.length;
            ctx.salt = saltMemory;
            ctx.saltlen = salt.length;
            ctx.secret = secretMemory;
            ctx.secretlen = secret != null ? secret.length : 0;
            ctx.ad = adMemory;
            ctx.adlen = ad != null ? ad.length : 0;
            ctx.t_cost = timeCost;
            ctx.m_cost = memoryCost;
            ctx.lanes = lanes;
            ctx.threads = threads;
            ctx.version = convertVersion(version);
            ctx.allocate_cbk = null;
            ctx.free_cbk = null;
            ctx.flags = ARGON2_DEFAULT_FLAGS;

            int argon2Type = convertType(type);

            int status = Argon2Library.INSTANCE.argon2_ctx(ctx, argon2Type);

            if (status != ARGON2_OK) {
                String errorMessage = Argon2Library.INSTANCE.argon2_error_message(status);
                throw new NativeInvocationJargon2BackendException(status, errorMessage);
            }

            byte[] hash = new byte[hashLength];
            outputMemory.read(0, hash, 0, hashLength);

            return hash;
        } finally {
            if (passwordMemory != null) {
                passwordMemory.clear(password.length);
                passwordMemory.dispose();
            }
            if (saltMemory != null) {
                saltMemory.dispose();
            }
            if (secretMemory != null) {
                secretMemory.clear(secret.length);
                secretMemory.dispose();
            }
            if (adMemory != null) {
                adMemory.dispose();
            }
            if (outputMemory != null) {
                outputMemory.clear(hashLength);
                outputMemory.dispose();
            }
        }
    }

    @Override
    public String encodedHash(Type type, Version version, int memoryCost, int timeCost, int lanes, int threads, int hashLength, byte[] secret, byte[] ad, byte[] salt, byte[] password, Map<String, Object> options) {
        byte[] rawHash = rawHash(type, version, memoryCost, timeCost, lanes, threads, hashLength, secret, ad, salt, password, options);
        try {
            return encodeString(type, version, timeCost, memoryCost, lanes, salt, rawHash);
        } catch (Exception e) {
            throw new Jargon2BackendException("Failed to encode hash", e);
        } finally {
            Arrays.fill(rawHash, (byte) 0x00);
        }
    }

    @Override
    public boolean verifyEncoded(String encodedHash, int threads, byte[] secret, byte[] ad, byte[] password, Map<String, Object> options) {
        if (encodedHash == null) {
            throw new Jargon2BackendException("Encoded hash cannot be null");
        }

        if ("".equals(encodedHash.trim())) {
            throw new Jargon2BackendException("Encoded hash cannot be empty");
        }

        DecodedHash decoded = decodeString(encodedHash);
        int lanes = decoded.parallelism;
        if (threads == -1) {
            threads = decoded.parallelism;
        }
        return verifyRaw(decoded.type, decoded.version, decoded.memoryCost, decoded.timeCost, lanes, threads, decoded.hash, secret, ad, decoded.salt, password, options);
    }

    @Override
    public boolean verifyRaw(Type type, Version version, int memoryCost, int timeCost, int lanes, int threads, byte[] rawHash, byte[] secret, byte[] ad, byte[] salt, byte[] password, Map<String, Object> options) {
        byte[] newHash = rawHash(type, version, memoryCost, timeCost, lanes, threads, rawHash.length, secret, ad, salt, password, options);
        return Arrays.equals(rawHash, newHash);
    }

    private DecodedHash decodeString(String encodedHash) {
        DecodedHash decoded = new DecodedHash();

        String[] parts = split(encodedHash, '$', 5);

        if (parts.length != 4 && parts.length != 5) {
            throw new Jargon2BackendException("Encoded hash is not properly formatted");
        }

        int typeIndex = 0;
        int versionIndex = 1;
        int optionsIndex = parts.length == 4 ? 1 : 2;
        int saltIndex = parts.length == 4 ? 2 : 3;
        int hashIndex = parts.length == 4 ? 3 : 4;

        String typeOpt = parts[typeIndex];
        decoded.type = convertType(typeOpt);

        if (parts.length == 5) {
            String versionOpt = parts[versionIndex];
            if (!versionOpt.startsWith("v=") || versionOpt.length() < 4) {
                throw new Jargon2BackendException("Encoded hash is not properly formatted");
            }
            decoded.version = convertVersion(versionOpt.substring(2));
        } else {
            decoded.version = Version.V10;
        }

        parseOptions(parts[optionsIndex], decoded);

        try {
            decoded.salt = base64decode(parts[saltIndex]);
        } catch (Exception e) {
            throw new Jargon2BackendException("Could not decode salt", e);
        }

        try {
            decoded.hash = base64decode(parts[hashIndex]);
        } catch (Exception e) {
            throw new Jargon2BackendException("Could not decode hash", e);
        }

        return decoded;
    }

    private void parseOptions(String options, DecodedHash decoded) {
        String[] opts = split(options, ',', 3);
        if (opts.length != 3) {
            throw new Jargon2BackendException("Wrong number of hashing options");
        }

        String memoryCostOption = opts[0];
        if (!memoryCostOption.startsWith("m=") || memoryCostOption.length() < 3) {
            throw new Jargon2BackendException("Wrong memory cost option");
        }
        try {
            decoded.memoryCost = Integer.parseInt(memoryCostOption.substring(2));
        } catch (Exception e) {
            throw new Jargon2BackendException("Memory cost option is invalid");
        }

        String timeCostOption = opts[1];
        if (!timeCostOption.startsWith("t=") || timeCostOption.length() < 3) {
            throw new Jargon2BackendException("Wrong time cost option");
        }
        try {
            decoded.timeCost = Integer.parseInt(timeCostOption.substring(2));
        } catch (Exception e) {
            throw new Jargon2BackendException("Time cost option is invalid");
        }

        String parallelismOption = opts[2];
        if (!parallelismOption.startsWith("p=") || parallelismOption.length() < 3) {
            throw new Jargon2BackendException("Wrong parallelism option");
        }
        try {
            decoded.parallelism = Integer.parseInt(parallelismOption.substring(2));
        } catch (Exception e) {
            throw new Jargon2BackendException("Parallelism option is invalid");
        }
    }

    private String encodeString(Type type, Version version, int timeCost, int memoryCost, int lanes, byte[] salt, byte[] hash) {
        StringBuilder sb = new StringBuilder();
        sb.append('$').append(type.getValue());
        if (version.getValue() > Version.V10.getValue()) {
            sb.append('$').append("v=").append(version.getValue());
        }
        sb.append('$').append("m=").append(memoryCost).append(",t=").append(timeCost).append(",p=").append(lanes);
        sb.append('$').append(base64encode(salt));
        sb.append('$').append(base64encode(hash));
        return sb.toString();
    }

    private DisposableMemory createMemory(int length) {
        return new DisposableMemory(length);
    }

    private DisposableMemory copyToMemory(byte[] arr) {
        if (arr == null) return null;
        DisposableMemory m = new DisposableMemory(arr.length);
        m.write(0, arr, 0, arr.length);
        return m;
    }

    private int convertVersion(Version version) {
        if (Version.V13.equals(version)) {
            return ARGON2_VERSION_13;
        } else if (Version.V10.equals(version)) {
            return ARGON2_VERSION_10;
        } else {
            throw new Jargon2BackendException("Null or unsupported version detected: " + version);
        }
    }

    private Version convertVersion(String version) {
        try {
            int v = Integer.parseInt(version);
            if (Version.V13.getValue() == v) {
                return Version.V13;
            } else if (Version.V10.getValue() == v) {
                return Version.V10;
            } else {
                throw new Jargon2BackendException("Invalid version number. Check encoded hash.");
            }
        } catch (NumberFormatException e) {
            throw new Jargon2BackendException("Non-numeric version. Check encoded hash.");
        }
    }

    private int convertType(Type type) {
        if (Type.ARGON2d.equals(type)) {
            return Argon2_d;
        } else if (Type.ARGON2i.equals(type)) {
            return Argon2_i;
        } else if (Type.ARGON2id.equals(type)) {
            return Argon2_id;
        } else {
            throw new Jargon2BackendException("Null or unsupported type detected: " + type);
        }
    }

    private Type convertType(String type) {
        if (Type.ARGON2d.getValue().equals(type)) {
            return Type.ARGON2d;
        } else if (Type.ARGON2i.getValue().equals(type)) {
            return Type.ARGON2i;
        } else if (Type.ARGON2id.getValue().equals(type)) {
            return Type.ARGON2id;
        } else {
            throw new Jargon2BackendException("Type did not decode properly. Check encoded hash.");
        }
    }

    static class DecodedHash {
        Type type;
        Version version;
        int memoryCost;
        int timeCost;
        int parallelism;
        byte[] salt;
        byte[] hash;
    }

    static class DisposableMemory extends Memory {
        DisposableMemory(long size) {
            super(size);
        }

        @Override
        public void dispose() {
            super.dispose();
        }
    }

    String[] split(String str, char delimiter, int maxTokens) {

        String[] tokens = new String[maxTokens];
        int from = 0;
        int i = 0;
        int len = str.length();

        while (from < len - 1) {
            if (i > tokens.length - 1) {
                break;
            }
            int delimIndex = str.indexOf(delimiter, from);
            if (delimIndex == -1) {
                if (from < len) {
                    tokens[i++] = str.substring(from, len);
                }
                break;
            }
            if (delimIndex > from) {
                tokens[i++] = str.substring(from, delimIndex);
            }
            from = delimIndex + 1;
        }

        if (i < tokens.length) {
            tokens = Arrays.copyOf(tokens, i);
        }

        return tokens;
    }

    private static final char[] encodeMapping = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
    };

    char[] base64encode(byte[] data) {
        int base64Length = data.length / 3 * 4;
        int mod3 = data.length % 3;
        if (mod3 != 0) {
            base64Length += (mod3 + 1);
        }
        char[] base64 = new char[base64Length];
        int i = 0;
        int j = 0;

        while (i < data.length - 2) {
            base64[j++] = encodeMapping[data[i] >>> 2 & 0b00111111];
            base64[j++] = encodeMapping[(data[i] << 4 & 0b00110000) | (data[++i] >>> 4 & 0b00001111)];
            base64[j++] = encodeMapping[(data[i] << 2 & 0b00111100) | (data[++i] >>> 6 & 0b00000011)];
            base64[j++] = encodeMapping[data[i++] & 0b00111111];
        }
        if (i == data.length - 1) {
            base64[j++] = encodeMapping[data[i] >>> 2 & 0b00111111];
            base64[j] = encodeMapping[data[i] << 4 & 0b00110000];
        } else if (i == data.length - 2) {
            base64[j++] = encodeMapping[data[i] >>> 2 & 0b00111111];
            base64[j++] = encodeMapping[(data[i] << 4 & 0b00110000) | (data[++i] >>> 4 & 0b00001111)];
            base64[j] = encodeMapping[data[i] << 2 & 0b00111100];
        }

        return base64;
    }

    private static final byte[] decodeMapping = {
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
            52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
            -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
            15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
            -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
            41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1
    };

    private static byte decodeMapping(char c) {
        byte decoded;
        if (c > 127 || (decoded = decodeMapping[c]) == -1) {
            throw new Jargon2BackendException("Invalid character in base64 string");
        }
        return decoded;
    }

    byte[] base64decode(String encoded) {
        int outputLength = encoded.length() / 4 * 3;
        int mod4 = encoded.length() % 4;
        if (mod4 != 0) {
            outputLength += (mod4 - 1);
        }
        byte[] output = new byte[outputLength];

        char[] buf = new char[4];
        int i = 0;
        int j = 0;

        while (i < encoded.length() - 3) {
            encoded.getChars(i, i + 4, buf, 0);
            output[j++] = (byte) ((decodeMapping(buf[0]) << 2) | (decodeMapping(buf[1]) >>> 4));
            output[j++] = (byte) ((decodeMapping(buf[1]) << 4) | (decodeMapping(buf[2]) >>> 2));
            output[j++] = (byte) ((decodeMapping(buf[2]) << 6) | (decodeMapping(buf[3]) & 0xFF));
            i += 4;
        }

        if (i == encoded.length() - 2) {
            encoded.getChars(i, i + 2, buf, 0);
            output[j] = (byte) ((decodeMapping(buf[0]) << 2) | (decodeMapping(buf[1]) >>> 4));
        } else if (i == encoded.length() - 3) {
            encoded.getChars(i, i + 3, buf, 0);
            output[j++] = (byte) ((decodeMapping(buf[0]) << 2) | (decodeMapping(buf[1]) >>> 4));
            output[j] = (byte) ((decodeMapping(buf[1]) << 4) | (decodeMapping(buf[2]) >>> 2));
        } else if (i != encoded.length()) {
            throw new Jargon2BackendException("Wrong number of characters in base64 string");
        }

        return output;
    }
}
