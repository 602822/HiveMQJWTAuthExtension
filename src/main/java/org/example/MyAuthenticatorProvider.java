package org.example;

import com.hivemq.extension.sdk.api.annotations.NotNull;
import com.hivemq.extension.sdk.api.annotations.Nullable;
import com.hivemq.extension.sdk.api.auth.Authenticator;
import com.hivemq.extension.sdk.api.auth.parameter.AuthenticatorProviderInput;
import com.hivemq.extension.sdk.api.services.auth.provider.AuthenticatorProvider;

public class MyAuthenticatorProvider implements AuthenticatorProvider {
    private final MyAuthenticator authenticator;

    public MyAuthenticatorProvider(MyAuthenticator authenticator) {
        this.authenticator = new MyAuthenticator();
    }

    @Override
    public @Nullable Authenticator getAuthenticator(@NotNull AuthenticatorProviderInput authenticatorProviderInput) {
      // returns a shareable authenticator instance, must be thread-safe / state-less
        return authenticator;
    }
}
