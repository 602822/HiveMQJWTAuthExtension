package org.example;

import com.hivemq.extension.sdk.api.annotations.NotNull;
import com.hivemq.extension.sdk.api.auth.SimpleAuthenticator;
import com.hivemq.extension.sdk.api.auth.parameter.SimpleAuthInput;
import com.hivemq.extension.sdk.api.auth.parameter.SimpleAuthOutput;
import com.hivemq.extension.sdk.api.packets.connect.ConnectPacket;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jose.util.StandardCharset;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.text.ParseException;
import java.util.*;

public class MyAuthenticator implements SimpleAuthenticator {

    private static final Logger log = LoggerFactory.getLogger(MyAuthenticator.class);


    //Json Web Key Set URL (where the JSON Web Keys are hosted)
    //contains the public key that can be used to verify JWT signatures
    private static final String JWKS_URL = "http://158.39.77.107:8081/realms/smartocean-testrealm/protocol/openid-connect/certs";

    private static final String EXPECTED_ISSUER = "http://158.39.77.107:8081/realms/smartocean-testrealm";

    private static final String CLAIM_ALLOWED_TOPICS = "allowed_topics";

    //who the token is intended/issued for
    private static final String EXPECTED_AUDIENCE = "hivemq-smartocean-testbroker";


    private final ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

    public MyAuthenticator() throws MalformedURLException {
        jwtProcessor = new DefaultJWTProcessor<>();

        //used to verify the signature of JWTs
        JWKSource<SecurityContext> keySource = JWKSourceBuilder
                .create(new URL(JWKS_URL))
                .retrying(true)
                .build();

        //Selects the appropriate key from the keySource to verify the signature of the JWT
        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, keySource);
        jwtProcessor.setJWSKeySelector(keySelector);

        JWTClaimsSet exactMatchClaims = new JWTClaimsSet.Builder()
                .issuer(EXPECTED_ISSUER)
                .build();

        Set<String> requiredClaims = new HashSet<>(Arrays.asList(
                JWTClaimNames.SUBJECT,
                JWTClaimNames.ISSUED_AT,
                JWTClaimNames.EXPIRATION_TIME,
                JWTClaimNames.JWT_ID
        ));

        //checks the type header of the JWT
        jwtProcessor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("JWT")));

        jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                exactMatchClaims,
                requiredClaims
        ));

    }

    @Override
    public void onConnect(@NotNull SimpleAuthInput simpleAuthInput, @NotNull SimpleAuthOutput simpleAuthOutput) {

        ConnectPacket connectPacket = simpleAuthInput.getConnectPacket();

        if (connectPacket.getPassword().isEmpty()) {
            simpleAuthOutput.failAuthentication();
            return;
        }

        try {

            String mqttClientId = connectPacket.getClientId();
            log.info("Authenticating client: {} ", mqttClientId);

            String jwtString = StandardCharset.UTF_8
                    .decode(connectPacket.getPassword().get())
                    .toString();

            System.out.println("jwt String: " + jwtString);

            //parses the token, ensures the token is in a valid JWT format
            SignedJWT signedJWT = SignedJWT.parse(jwtString);
            //verifies the signature, checks issuer, audience, expiration and required claims
            JWTClaimsSet claims = jwtProcessor.process(signedJWT, null);


            System.out.println("JWT: " + signedJWT);


             List<String> allowedTopicsList = Optional.ofNullable((List<String>) claims.getClaim(CLAIM_ALLOWED_TOPICS)).orElse(List.of());

            List<String> tokenAudience = claims.getAudience();
            if (tokenAudience == null || !tokenAudience.contains(EXPECTED_AUDIENCE)) {
                log.error("Invalid audience claim for {}", mqttClientId);
                simpleAuthOutput.failAuthentication();
                return;
            }

            //Store allowed topics as comma separated string
            String allowedTopics = String.join(",", allowedTopicsList);
            simpleAuthInput.getConnectionInformation().getConnectionAttributeStore().put(CLAIM_ALLOWED_TOPICS, ByteBuffer.wrap(allowedTopics.getBytes(StandardCharset.UTF_8)));


            //token is valid
            log.info("Authenticated user: {}", claims.getSubject());
            simpleAuthOutput.authenticateSuccessfully();

        } catch (ParseException | BadJOSEException e) {
            log.error("JWT validation failed: {}", e.getMessage());
            simpleAuthOutput.failAuthentication();
        } catch (JOSEException e) {
            log.error("JWT processing error: {}", e.getMessage());
            simpleAuthOutput.failAuthentication();
        }
    }
}
