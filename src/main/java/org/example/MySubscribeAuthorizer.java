package org.example;

import com.hivemq.extension.sdk.api.annotations.NotNull;
import com.hivemq.extension.sdk.api.auth.SubscriptionAuthorizer;
import com.hivemq.extension.sdk.api.auth.parameter.PublishAuthorizerInput;
import com.hivemq.extension.sdk.api.auth.parameter.SubscriptionAuthorizerInput;
import com.hivemq.extension.sdk.api.auth.parameter.SubscriptionAuthorizerOutput;
import com.hivemq.extension.sdk.api.packets.subscribe.SubackReasonCode;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public class MySubscribeAuthorizer implements SubscriptionAuthorizer {
    @Override
    public void authorizeSubscribe(@NotNull SubscriptionAuthorizerInput subscriptionAuthorizerInput, @NotNull SubscriptionAuthorizerOutput subscriptionAuthorizerOutput) {

        String clientId = subscriptionAuthorizerInput.getClientInformation().getClientId();
        String topic = subscriptionAuthorizerInput.getSubscription().getTopicFilter();
        Optional<String> location = getClaim("location", subscriptionAuthorizerInput);
        Optional<String> provider = getClaim("provider", subscriptionAuthorizerInput);
        Optional<String> allowedTopicsString = getClaim("allowed_topics", subscriptionAuthorizerInput);

        if(location.isEmpty() || provider.isEmpty()) {
            subscriptionAuthorizerOutput.failAuthorization(SubackReasonCode.NOT_AUTHORIZED);
            return;
        }

        // {location}/{provider}/{clientId}/#
        String selfTopicPattern = String.format("%s/%s/%s/#", provider.get(), location.get(), clientId);

        List<String> explicitAllowedTopics = allowedTopicsString.map(s -> Arrays.asList(s.split(","))).orElse(List.of());

        //check if topic matches self topic pattern
        if(topicMatches(selfTopicPattern, topic)) {
            subscriptionAuthorizerOutput.authorizeSuccessfully();
            return;

        }

        //check if topic matches any explicitly allowed topics
        if(explicitAllowedTopics.stream().anyMatch(allowedTopic -> allowedTopic.equals(topic))) {
            subscriptionAuthorizerOutput.authorizeSuccessfully();
            return;
        }

        subscriptionAuthorizerOutput.failAuthorization(SubackReasonCode.NOT_AUTHORIZED);


    }

    Optional<String> getClaim(String name, SubscriptionAuthorizerInput subscriptionAuthorizerInput) {
        var attributeStore = subscriptionAuthorizerInput.getConnectionInformation().getConnectionAttributeStore();
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
