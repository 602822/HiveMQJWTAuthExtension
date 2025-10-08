package org.example;

import com.hivemq.extension.sdk.api.annotations.NotNull;
import com.hivemq.extension.sdk.api.auth.SubscriptionAuthorizer;
import com.hivemq.extension.sdk.api.auth.parameter.SubscriptionAuthorizerInput;
import com.hivemq.extension.sdk.api.auth.parameter.SubscriptionAuthorizerOutput;
import com.hivemq.extension.sdk.api.packets.subscribe.SubackReasonCode;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

public class MySubscribeAuthorizer implements SubscriptionAuthorizer {
    @Override
    public void authorizeSubscribe(@NotNull SubscriptionAuthorizerInput subscriptionAuthorizerInput, @NotNull SubscriptionAuthorizerOutput subscriptionAuthorizerOutput) {

        @NotNull Optional<ByteBuffer> rolesBuffer = subscriptionAuthorizerInput.getConnectionInformation().getConnectionAttributeStore().get("roles");

        if(rolesBuffer.isPresent()) {
            String roleString = StandardCharsets.UTF_8.decode(rolesBuffer.get()).toString();
            if(roleString.contains("mqtt:subscribe")) {
                subscriptionAuthorizerOutput.authorizeSuccessfully();
                return;
            }
        }
        subscriptionAuthorizerOutput.failAuthorization(SubackReasonCode.NOT_AUTHORIZED);

    }
}
