package org.example;

import com.hivemq.extension.sdk.api.auth.Authorizer;
import com.hivemq.extension.sdk.api.auth.parameter.AuthorizerProviderInput;

import com.hivemq.extension.sdk.api.services.auth.provider.AuthorizerProvider;
import com.hivemq.extension.sdk.api.annotations.Nullable;
import com.hivemq.extension.sdk.api.annotations.NotNull;


public class MyAuthorizerProvider implements AuthorizerProvider {

    private final MyClientAuthorizer myClientAuthorizer = new MyClientAuthorizer();

    @Override
    public @Nullable Authorizer getAuthorizer(@NotNull AuthorizerProviderInput authorizerProviderInput) {
        return myClientAuthorizer;
    }
}
