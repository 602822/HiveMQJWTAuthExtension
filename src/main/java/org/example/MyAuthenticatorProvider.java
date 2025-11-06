package org.example;

import com.hivemq.extension.sdk.api.annotations.NotNull;
import com.hivemq.extension.sdk.api.annotations.Nullable;
import com.hivemq.extension.sdk.api.auth.Authenticator;
import com.hivemq.extension.sdk.api.auth.parameter.AuthenticatorProviderInput;
import com.hivemq.extension.sdk.api.services.auth.provider.AuthenticatorProvider;

import java.net.MalformedURLException;

public class MyAuthenticatorProvider implements AuthenticatorProvider {
    private final MyAuthenticator authenticator;

    public MyAuthenticatorProvider() throws MalformedURLException {
        try {
            this.authenticator = new MyAuthenticator();
        } catch (MalformedURLException e) {
            throw new RuntimeException("Failed to initialize authenticator", e);
        }
    }

    @Override
    public @Nullable Authenticator getAuthenticator(@NotNull AuthenticatorProviderInput authenticatorProviderInput) {
        return authenticator;
    }
}
