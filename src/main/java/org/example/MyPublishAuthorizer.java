package org.example;

import com.hivemq.extension.sdk.api.annotations.NotNull;
import com.hivemq.extension.sdk.api.auth.PublishAuthorizer;
import com.hivemq.extension.sdk.api.auth.parameter.PublishAuthorizerInput;
import com.hivemq.extension.sdk.api.auth.parameter.PublishAuthorizerOutput;
import com.hivemq.extension.sdk.api.packets.publish.AckReasonCode;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public class MyPublishAuthorizer implements PublishAuthorizer {
    @Override
    public void authorizePublish(@NotNull PublishAuthorizerInput publishAuthorizerInput, @NotNull PublishAuthorizerOutput publishAuthorizerOutput) {

        String clientId = publishAuthorizerInput.getClientInformation().getClientId();
        String topic = publishAuthorizerInput.getPublishPacket().getTopic();
        Optional<String> location = getClaim("location", publishAuthorizerInput);
        Optional<String> provider = getClaim("provider", publishAuthorizerInput);
        Optional<String> allowedTopicsString = getClaim("allowed_topics", publishAuthorizerInput);

        if(location.isEmpty() || provider.isEmpty()) {
            publishAuthorizerOutput.failAuthorization(AckReasonCode.NOT_AUTHORIZED);
            return;
        }

        // {location}/{provider}/{clientId}/#
        String selfTopicPattern = String.format("%s/%s/%s/#", provider.get(), location.get(), clientId);

        List<String> explicitAllowedTopics = allowedTopicsString.map(s -> Arrays.asList(s.split(","))).orElse(List.of());


        //check if topic matches self topic pattern
        if(topicMatches(selfTopicPattern, topic)) {
            publishAuthorizerOutput.authorizeSuccessfully();
            return;
        }

        //check if topic matches any explicitly allowed topics
        if(explicitAllowedTopics.stream().anyMatch(allowedTopic -> allowedTopic.equals(topic))) {
            publishAuthorizerOutput.authorizeSuccessfully();
            return;
        }

        publishAuthorizerOutput.failAuthorization(AckReasonCode.NOT_AUTHORIZED);
    }

    Optional<String> getClaim(String name, PublishAuthorizerInput publishAuthorizerInput) {
        var attributeStore = publishAuthorizerInput.getConnectionInformation().getConnectionAttributeStore();
        Optional<ByteBuffer> buffer = attributeStore.get(name);
        return buffer.map(byteBuffer -> StandardCharsets.UTF_8.decode(byteBuffer).toString());
    }

    private boolean topicMatches(String pattern, String topic) {
        if(pattern.endsWith("/#")) {
            String prefix = pattern.substring(0, pattern.length() - 2);
            return topic.startsWith(prefix);
        }
        return pattern.equals(topic);
    }



}
