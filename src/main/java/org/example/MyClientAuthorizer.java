package org.example;

import com.hivemq.extension.sdk.api.annotations.NotNull;
import com.hivemq.extension.sdk.api.auth.PublishAuthorizer;
import com.hivemq.extension.sdk.api.auth.SubscriptionAuthorizer;
import com.hivemq.extension.sdk.api.auth.parameter.PublishAuthorizerInput;
import com.hivemq.extension.sdk.api.auth.parameter.PublishAuthorizerOutput;
import com.hivemq.extension.sdk.api.auth.parameter.SubscriptionAuthorizerInput;
import com.hivemq.extension.sdk.api.auth.parameter.SubscriptionAuthorizerOutput;
import com.hivemq.extension.sdk.api.packets.publish.AckReasonCode;
import com.hivemq.extension.sdk.api.packets.subscribe.SubackReasonCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

public class MyClientAuthorizer implements PublishAuthorizer, SubscriptionAuthorizer {

    private final @NotNull Logger log = LoggerFactory.getLogger(MyClientAuthorizer.class);

    @Override
    public void authorizePublish(@NotNull PublishAuthorizerInput publishAuthorizerInput, @NotNull PublishAuthorizerOutput publishAuthorizerOutput) {

        final String clientId = publishAuthorizerInput.getClientInformation().getClientId();
        final String topic = publishAuthorizerInput.getPublishPacket().getTopic();
        log.info("Authorizing publish for clientId: {}, topic: {} ", clientId, topic);


        Optional<String> allowedTopicsString = getPublishClaim(publishAuthorizerInput);

        log.info("allowed_topics: {}", allowedTopicsString.orElse("null"));


        if (allowedTopicsString.isPresent()) {
            String[] allowedTopics = allowedTopicsString.get().split(",");
            for (String allowedTopic : allowedTopics) {
                if (topic.equals(allowedTopic)) {
                    publishAuthorizerOutput.authorizeSuccessfully();
                    return;
                }
            }
        }

        log.error("Authorization failed for clientId: {}, topic: {}", clientId, topic);
        publishAuthorizerOutput.failAuthorization(AckReasonCode.NOT_AUTHORIZED);


    }

    @Override
    public void authorizeSubscribe(@NotNull SubscriptionAuthorizerInput subscriptionAuthorizerInput, @NotNull SubscriptionAuthorizerOutput subscriptionAuthorizerOutput) {
        final String clientId = subscriptionAuthorizerInput.getClientInformation().getClientId();
        final String topic = subscriptionAuthorizerInput.getSubscription().getTopicFilter();
        log.info("Authorizing subscribe for clientId: {}, topic: {} ", clientId, topic);

        Optional<String> allowedTopicsString = getSubscribeClaim(subscriptionAuthorizerInput);
        log.info("allowed_topics: {}", allowedTopicsString.orElse("null"));


        if (allowedTopicsString.isPresent()) {
            String[] allowedTopics = allowedTopicsString.get().split(",");
            for (String allowedTopic : allowedTopics) {
                if (topic.equals(allowedTopic)) {
                    subscriptionAuthorizerOutput.authorizeSuccessfully();
                    return;
                }
            }
        }

        log.error("Authorization failed for clientId: {}, topic: {}", clientId, topic);
        subscriptionAuthorizerOutput.failAuthorization(SubackReasonCode.NOT_AUTHORIZED);

    }

    Optional<String> getPublishClaim(PublishAuthorizerInput publishAuthorizerInput) {
        var attributeStore = publishAuthorizerInput.getConnectionInformation().getConnectionAttributeStore();
        Optional<ByteBuffer> buffer = attributeStore.get("allowed_topics");
        return buffer.map(byteBuffer -> StandardCharsets.UTF_8.decode(byteBuffer).toString());
    }

    Optional<String> getSubscribeClaim(SubscriptionAuthorizerInput subscriptionAuthorizerInput) {
        var attributeStore = subscriptionAuthorizerInput.getConnectionInformation().getConnectionAttributeStore();
        Optional<ByteBuffer> buffer = attributeStore.get("allowed_topics");
        return buffer.map(byteBuffer -> StandardCharsets.UTF_8.decode(byteBuffer).toString());
    }


}

