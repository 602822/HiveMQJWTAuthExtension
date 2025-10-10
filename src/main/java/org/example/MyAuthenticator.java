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
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

public class MyAuthenticator implements SimpleAuthenticator {

    private static final Logger log = LoggerFactory.getLogger(MyAuthenticator.class);

    //Replace with Keycloak realm's JWKS URL
    private static final String JWKS_URL = "https://<keycloak-host>/realms/<realm>/protocol/openid-connect/certs";

    //Replace with Keycloak realm's issuer Url
    private static final String EXPECTED_ISSUER = "https://<keycloak-host>/realms/<realm>";


    private final ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

    public MyAuthenticator() throws MalformedURLException {
        jwtProcessor = new DefaultJWTProcessor<>();

        JWKSource<SecurityContext> keySource = JWKSourceBuilder
                .create(new URL(JWKS_URL))
                .retrying(true)
                .build();

        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, keySource);
        jwtProcessor.setJWSKeySelector(keySelector);

        //check that token is specifically an access token
        jwtProcessor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("at+jwt")));

        //required claims, add aud or scp to enforce scope
        jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                //the iss must be equal to Keycloaks realm URL
                new JWTClaimsSet.Builder().issuer(EXPECTED_ISSUER).build(),
                // token must include:
                new HashSet<>(Arrays.asList(
                        JWTClaimNames.SUBJECT,
                        JWTClaimNames.ISSUED_AT,
                        JWTClaimNames.EXPIRATION_TIME,
                        JWTClaimNames.JWT_ID
                ))
        ));

    }

    @Override
    public void onConnect(@NotNull SimpleAuthInput simpleAuthInput, @NotNull SimpleAuthOutput simpleAuthOutput) {
        ConnectPacket connectPacket = simpleAuthInput.getConnectPacket();

        if (connectPacket.getPassword().isEmpty()) {
            simpleAuthOutput.failAuthentication();
        }

        try {

            String mqttClientId = connectPacket.getClientId();
            log.info("Authenticating client: {} ", mqttClientId);

            String jwtString = StandardCharset.UTF_8
                    .decode(connectPacket.getPassword().get())
                    .toString();

            //parse + validate jwt token
            SignedJWT signedJWT = SignedJWT.parse(jwtString);
            JWTClaimsSet claims = jwtProcessor.process(signedJWT, null);


            Map<String, Object> realmAccess = (Map<String, Object>) claims.getClaim("realm_access");


            if (realmAccess == null) {
                log.error("No realm-access claim found for client: {}", mqttClientId);
                simpleAuthOutput.failAuthentication();
                return;
            }

            List<String> roles = (List<String>) realmAccess.get("roles");
            log.info("Roles for {}: {} ", mqttClientId, roles);

            if (roles == null || !realmAccess.containsKey("roles")) {
                log.error("No roles assigned to {}", mqttClientId);
                simpleAuthOutput.failAuthentication();
                return;
            }

            if (!roles.contains("mqtt:connect")) {
                log.error("Missing mqtt:connect role for {}", mqttClientId);
                simpleAuthOutput.failAuthentication();
                return;
            }

            //Storing the roles in the connection attribute store for later use in the authorizer
            String rolesString = String.join(",", roles);
            ByteBuffer rolesBuffer = ByteBuffer.wrap(rolesString.getBytes(StandardCharset.UTF_8));
            simpleAuthInput.getConnectionInformation().getConnectionAttributeStore().put("roles", rolesBuffer);


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
