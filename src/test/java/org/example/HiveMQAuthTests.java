package org.example;

import com.hivemq.client.mqtt.datatypes.MqttQos;
import com.hivemq.client.mqtt.mqtt5.Mqtt5BlockingClient;
import com.hivemq.client.mqtt.mqtt5.Mqtt5Client;
import com.hivemq.client.mqtt.mqtt5.exceptions.Mqtt5ConnAckException;
import com.hivemq.client.mqtt.mqtt5.message.connect.Mqtt5Connect;
import org.junit.Rule;
import org.junit.Test;
import org.testcontainers.hivemq.HiveMQContainer;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import java.io.IOException;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

public class HiveMQAuthTests {

    Properties props = ConfigLoader.load();

    String s1ClientId = props.getProperty("S1CLIENTID");
    String s1ClientSecret = props.getProperty("S1CLIENTSECRET");

    String s2ClientId = props.getProperty("S2CLIENTID");
    String s2ClientSecret = props.getProperty("S2CLIENTSECRET");


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

        //Missing 'provider' claim for sensor-2
        String jwtToken = KeycloakAuth.getTokenSensor(s2ClientId, s2ClientSecret);

        Mqtt5Connect connectPacket = Mqtt5Connect.builder()
                .simpleAuth()
                .username(s2ClientId)
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

        String topic = "underwater/temperature";
        double temperature = 25.5;

        assertDoesNotThrow(() -> {
            client.publishWith()
                    .topic(topic)
                    .qos(MqttQos.AT_LEAST_ONCE)
                    .payload(String.valueOf(temperature).getBytes())
                    .send();
        }, "Publishing to authorized topic should succeed");
    }


}
