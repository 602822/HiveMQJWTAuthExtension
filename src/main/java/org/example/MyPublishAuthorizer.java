package org.example;

import com.hivemq.extension.sdk.api.annotations.NotNull;
import com.hivemq.extension.sdk.api.auth.PublishAuthorizer;
import com.hivemq.extension.sdk.api.auth.parameter.PublishAuthorizerInput;
import com.hivemq.extension.sdk.api.auth.parameter.PublishAuthorizerOutput;
import com.hivemq.extension.sdk.api.packets.publish.AckReasonCode;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

public class MyPublishAuthorizer implements PublishAuthorizer {
    @Override
    public void authorizePublish(@NotNull PublishAuthorizerInput publishAuthorizerInput, @NotNull PublishAuthorizerOutput publishAuthorizerOutput) {
        @NotNull Optional<ByteBuffer> rolesBuffer = publishAuthorizerInput.getConnectionInformation().getConnectionAttributeStore().get("roles");

        if(rolesBuffer.isPresent()) {
            String roleString = StandardCharsets.UTF_8.decode(rolesBuffer.get()).toString();
            if(roleString.contains("mqtt:publish")) {
                publishAuthorizerOutput.authorizeSuccessfully();
                return;
            }
        }
        publishAuthorizerOutput.failAuthorization(AckReasonCode.NOT_AUTHORIZED);
    }
}
