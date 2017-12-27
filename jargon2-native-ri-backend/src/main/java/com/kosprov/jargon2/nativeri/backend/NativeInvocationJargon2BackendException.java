package com.kosprov.jargon2.nativeri.backend;

import com.kosprov.jargon2.spi.Jargon2BackendException;

class NativeInvocationJargon2BackendException extends Jargon2BackendException {

    NativeInvocationJargon2BackendException(int status, String errorMessage) {
        super("Exception during native invocation. Status: " + status + ", error message: " + errorMessage);
    }
}
