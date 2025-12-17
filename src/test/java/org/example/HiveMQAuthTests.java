package org.example;

import com.hivemq.client.mqtt.MqttGlobalPublishFilter;
import com.hivemq.client.mqtt.datatypes.MqttQos;
import com.hivemq.client.mqtt.mqtt5.Mqtt5BlockingClient;
import com.hivemq.client.mqtt.mqtt5.Mqtt5Client;
import com.hivemq.client.mqtt.mqtt5.exceptions.Mqtt5ConnAckException;
import com.hivemq.client.mqtt.mqtt5.message.connect.Mqtt5Connect;
import com.hivemq.client.mqtt.mqtt5.message.publish.Mqtt5Publish;
import org.junit.Rule;
import org.junit.Test;
import org.testcontainers.hivemq.HiveMQContainer;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import java.awt.*;
import java.io.IOException;
import java.net.URI;
import java.util.Properties;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.*;

public class HiveMQAuthTests {

    Properties props = ConfigLoader.load();

    String s1ClientId = props.getProperty("S1CLIENTID");
    String s1ClientSecret = props.getProperty("S1CLIENTSECRET");

    String s2ClientId = props.getProperty("S2CLIENTID");
    String s2ClientSecret = props.getProperty("S2CLIENTSECRET");

    String s4ClientId = props.getProperty("S4CLIENTID");
    String s4ClientSecret = props.getProperty("S4CLIENTSECRET");


    @Rule
    public HiveMQContainer hivemq = new HiveMQContainer(DockerImageName.parse("hivemq/hivemq-ce:latest"))
            .withExtension(MountableFile.forHostPath(
                    "C:/Users/vefje/IdeaProjects/HiveMQJWTAuthExtension1/target/HiveMQJWTAuthExtension1-1.0-SNAPSHOT-distribution/HiveMQJWTAuthExtension1"
            ));

    public HiveMQAuthTests() throws IOException {
    }


    @Test
    public void testAuthFailForMissingJWT() {
        Mqtt5BlockingClient client = Mqtt5Client.builder()
                .serverHost(hivemq.getHost())
                .serverPort(hivemq.getMqttPort())
                .buildBlocking();

        Mqtt5Connect connectPacket = Mqtt5Connect.builder()
                .simpleAuth()
                .username("testClient")
                .password(new byte[0]) // No JWT token provided
                .applySimpleAuth()
                .build();
        assertThrows(Mqtt5ConnAckException.class, () -> client.connect(connectPacket));

    }

    @Test
    public void testAuthSucceedsWithValidJWTForSensor() throws IOException, InterruptedException {
        Mqtt5BlockingClient client = Mqtt5Client.builder()
                .serverHost(hivemq.getHost())
                .serverPort(hivemq.getMqttPort())
                .buildBlocking();

        String jwtToken = KeycloakAuth.getTokenSensor(s1ClientId, s1ClientSecret);

        Mqtt5Connect connectPacket = Mqtt5Connect.builder()
                .simpleAuth()
                .username(s1ClientId)
                .password(jwtToken.getBytes())
                .applySimpleAuth()
                .build();

        client.connect(connectPacket);
        assertTrue(client.getState().isConnected(), "Client should be connected with valid JWT token");
    }

    @Test
    public void testAuthFailForJWTWithMissingClaim() throws IOException, InterruptedException {
        Mqtt5BlockingClient client = Mqtt5Client.builder()
                .serverHost(hivemq.getHost())
                .serverPort(hivemq.getMqttPort())
                .buildBlocking();

        //Missing 'aud' claim for sensor-4
        String jwtToken = KeycloakAuth.getTokenSensor(s4ClientId, s4ClientSecret);

        Mqtt5Connect connectPacket = Mqtt5Connect.builder()
                .simpleAuth()
                .username(s4ClientId)
                .password(jwtToken.getBytes())
                .applySimpleAuth()
                .build();

        assertThrows(Mqtt5ConnAckException.class, () -> client.connect(connectPacket));
    }


    @Test
    public void testFailPublishToUnauthorizedTopic() throws IOException, InterruptedException {
        Mqtt5BlockingClient client = Mqtt5Client.builder()
                .serverHost(hivemq.getHost())
                .serverPort(hivemq.getMqttPort())
                .buildBlocking();

        String jwtToken = KeycloakAuth.getTokenSensor(s1ClientId, s1ClientSecret);


        Mqtt5Connect connectPacket = Mqtt5Connect.builder()
                .simpleAuth()
                .username(s1ClientId)
                .password(jwtToken.getBytes())
                .applySimpleAuth()
                .build();

        client.connect(connectPacket);

        String topic = "smartocean/123";
        double temperature = 25.5;

        assertThrows(Exception.class, () -> {
            client.publishWith()
                    .topic(topic)
                    .qos(MqttQos.AT_LEAST_ONCE)
                    .payload(String.valueOf(temperature).getBytes())
                    .send();
        }, "Publishing to unauthorized topic should fail");
    }

    @Test
    public void testSucceedPublishToAuthorizedTopic() throws IOException, InterruptedException {
        Mqtt5BlockingClient client = Mqtt5Client.builder()
                .serverHost(hivemq.getHost())
                .serverPort(hivemq.getMqttPort())
                .buildBlocking();

        String jwtToken = KeycloakAuth.getTokenSensor(s1ClientId, s1ClientSecret);


        Mqtt5Connect connectPacket = Mqtt5Connect.builder()
                .simpleAuth()
                .username(s1ClientId)
                .password(jwtToken.getBytes())
                .applySimpleAuth()
                .build();

        client.connect(connectPacket);

        String topic = "smartocean/Austevoll/Aanderaa/sensor-1/temperature";
        double temperature = 25.5;

        assertDoesNotThrow(() -> {
            client.publishWith()
                    .topic(topic)
                    .qos(MqttQos.AT_LEAST_ONCE)
                    .payload(String.valueOf(temperature).getBytes())
                    .send();
        }, "Publishing to authorized topic should succeed");
    }

    @Test
    public void testAuthorizationSucceedsUsingPlusWildcard() throws IOException, InterruptedException {

        Mqtt5BlockingClient subscriber = Mqtt5Client.builder()
                .serverHost(hivemq.getHost())
                .serverPort(hivemq.getMqttPort())
                .buildBlocking();

        String clientId = props.getProperty("CLIENT_ID");
        String redirectUri = props.getProperty("REDIRECT_URI");

        String codeVerifier = PKCEUtils.generateCodeVerifier();
        String codeChallenge = PKCEUtils.generateCodeChallenge(codeVerifier);
        String authUrl = PKCEUtils.generateAuthURL(clientId, redirectUri, codeChallenge);

        System.out.println("Opening browser for Keycloak login...");
        if (Desktop.isDesktopSupported()) {
            Desktop.getDesktop().browse(URI.create(authUrl));
        }

        CompletableFuture<String> codeFuture = AuthServer.waitForAuthCode(8081);
        String authCode = codeFuture.join();
        System.out.println("Received auth code: " + authCode);

        TokenResponse tokenResponse = KeycloakAuthSubscriber.getTokenUserPKCE(authCode, redirectUri, clientId, codeVerifier);
        String subscriberJWT = tokenResponse.accessToken();

        subscriber.connect(Mqtt5Connect.builder()
                .simpleAuth()
                .username(clientId)
                .password(subscriberJWT.getBytes())
                .applySimpleAuth()
                .build());

        subscriber.subscribeWith()
                .topicFilter("smartocean/Austevoll/Aanderaa/sensor-1/+")
                .qos(MqttQos.AT_LEAST_ONCE)
                .send();

        Mqtt5BlockingClient client = Mqtt5Client.builder()
                .serverHost(hivemq.getHost())
                .serverPort(hivemq.getMqttPort())
                .buildBlocking();

        String jwtToken = KeycloakAuth.getTokenSensor(s1ClientId, s1ClientSecret);

        client.connect(Mqtt5Connect.builder()
                .simpleAuth()
                .username(s1ClientId)
                .password(jwtToken.getBytes())
                .applySimpleAuth()
                .build());

        String topicTemperature = "smartocean/Austevoll/Aanderaa/sensor-1/temperature";
        String topicPressure = "smartocean/Austevoll/Aanderaa/sensor-1/pressure";
        double temperature = 25.5;
        double pressure = 1.2;


        try (Mqtt5BlockingClient.Mqtt5Publishes publishes = subscriber.publishes(MqttGlobalPublishFilter.ALL)) {

            client.publishWith()
                    .topic(topicTemperature)
                    .qos(MqttQos.AT_LEAST_ONCE)
                    .payload(String.valueOf(temperature).getBytes())
                    .send();

            client.publishWith()
                    .topic(topicPressure)
                    .qos(MqttQos.AT_LEAST_ONCE)
                    .payload(String.valueOf(pressure).getBytes())
                    .send();


            Mqtt5Publish msg1 = publishes.receive();

            System.out.println("Received 1: " + new String(msg1.getPayloadAsBytes()));
            assertEquals(topicTemperature, msg1.getTopic().toString());
            assertEquals("25.5", new String(msg1.getPayloadAsBytes()));

            Mqtt5Publish msg2 = publishes.receive();

            System.out.println("Received 2: " + new String(msg2.getPayloadAsBytes()));
            assertEquals(topicPressure, msg2.getTopic().toString());
            assertEquals("1.2", new String(msg2.getPayloadAsBytes()));
        }

        client.disconnect();
        subscriber.disconnect();
    }

    @Test
    public void testAuthorizationSucceedsUsingHashtagWildcard() throws IOException, InterruptedException {

        Mqtt5BlockingClient subscriber = Mqtt5Client.builder()
                .serverHost(hivemq.getHost())
                .serverPort(hivemq.getMqttPort())
                .buildBlocking();

        String clientId = props.getProperty("CLIENT_ID");
        String redirectUri = props.getProperty("REDIRECT_URI");

        String codeVerifier = PKCEUtils.generateCodeVerifier();
        String codeChallenge = PKCEUtils.generateCodeChallenge(codeVerifier);
        String authUrl = PKCEUtils.generateAuthURL(clientId, redirectUri, codeChallenge);

        System.out.println("Opening browser for Keycloak login...");
        if (Desktop.isDesktopSupported()) {
            Desktop.getDesktop().browse(URI.create(authUrl));
        }

        CompletableFuture<String> codeFuture = AuthServer.waitForAuthCode(8081);
        String authCode = codeFuture.join();
        System.out.println("Received auth code: " + authCode);

        TokenResponse tokenResponse = KeycloakAuthSubscriber.getTokenUserPKCE(authCode, redirectUri, clientId, codeVerifier);
        String subscriberJWT = tokenResponse.accessToken();

        subscriber.connect(Mqtt5Connect.builder()
                .simpleAuth()
                .username(clientId)
                .password(subscriberJWT.getBytes())
                .applySimpleAuth()
                .build());

        subscriber.subscribeWith()
                .topicFilter("smartocean/Austevoll/#")
                .qos(MqttQos.AT_LEAST_ONCE)
                .send();

        Mqtt5BlockingClient sensor1 = Mqtt5Client.builder()
                .serverHost(hivemq.getHost())
                .serverPort(hivemq.getMqttPort())
                .buildBlocking();

        String jwtToken = KeycloakAuth.getTokenSensor(s1ClientId, s1ClientSecret);

        sensor1.connect(Mqtt5Connect.builder()
                .simpleAuth()
                .username(s1ClientId)
                .password(jwtToken.getBytes())
                .applySimpleAuth()
                .build());


        Mqtt5BlockingClient sensor2 = Mqtt5Client.builder()
                .serverHost(hivemq.getHost())
                .serverPort(hivemq.getMqttPort())
                .buildBlocking();

        String jwtToken2 = KeycloakAuth.getTokenSensor(s2ClientId, s2ClientSecret);

        sensor2.connect(Mqtt5Connect.builder()
                .simpleAuth()
                .username(s2ClientId)
                .password(jwtToken2.getBytes())
                .applySimpleAuth()
                .build());



        String topicTemperature = "smartocean/Austevoll/Aanderaa/sensor-1/temperature";
        String topicPressure = "smartocean/Austevoll/W-sense/sensor-2/pressure";
        double temperature = 25.5;
        double pressure = 1.2;


        try (Mqtt5BlockingClient.Mqtt5Publishes publishes = subscriber.publishes(MqttGlobalPublishFilter.ALL)) {

            sensor1.publishWith()
                    .topic(topicTemperature)
                    .qos(MqttQos.AT_LEAST_ONCE)
                    .payload(String.valueOf(temperature).getBytes())
                    .send();

            sensor2.publishWith()
                    .topic(topicPressure)
                    .qos(MqttQos.AT_LEAST_ONCE)
                    .payload(String.valueOf(pressure).getBytes())
                    .send();


            Mqtt5Publish msg1 = publishes.receive();

            System.out.println("Received 1: " + new String(msg1.getPayloadAsBytes()));
            assertEquals(topicTemperature, msg1.getTopic().toString());
            assertEquals("25.5", new String(msg1.getPayloadAsBytes()));

            Mqtt5Publish msg2 = publishes.receive();

            System.out.println("Received 2: " + new String(msg2.getPayloadAsBytes()));
            assertEquals(topicPressure, msg2.getTopic().toString());
            assertEquals("1.2", new String(msg2.getPayloadAsBytes()));
        }

        sensor1.disconnect();
        sensor2.disconnect();
        subscriber.disconnect();
    }


}
