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
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashSet;

public class MyAuthenticator implements SimpleAuthenticator {

    //Replace with Keycloak realm's JWKS URL
    private static final String JWKS_URL = "https://<keycloak-host>/realms/<realm>/protocol/openid-connect/certs";

    //Replace with Keycloak realm's issuer Url
    private static final String EXPECTED_ISSUER = "https://<keycloak-host>/realms/<realm>";

    //the audience claim i expect for MQTT (who the token is intended for
    private static final String EXPECTED_AUDIENCE = "mqtt-broker"; //temporary

//The scopes I expect the client to have
    private static final String REQUIRED_SCOPE = "mqtt:connect"; //temporary


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
        if (connectPacket.getPassword().isPresent()) {
            simpleAuthOutput.failAuthentication();
        }

        try {
            String jwtString = StandardCharset.UTF_8
                    .decode(connectPacket.getPassword().get())
                    .toString();

            //parse + validate jwt token
            SignedJWT signedJWT = SignedJWT.parse(jwtString);
            JWTClaimsSet claims = jwtProcessor.process(signedJWT, null);


            if(!claims.getAudience().contains(EXPECTED_AUDIENCE)) {
                System.err.println("Invalid audience: " + claims.getAudience());
                simpleAuthOutput.failAuthentication();
                return;
            }

            if(claims.getStringListClaim("scp") == null || !claims.getStringListClaim("scp").contains(REQUIRED_SCOPE)) {
                System.err.println("Missing required scope:" + REQUIRED_SCOPE);
                simpleAuthOutput.failAuthentication();
                return;
            }


            //token is valid
            System.out.println("Authenticated user: " + claims.getSubject());
            simpleAuthOutput.authenticateSuccessfully();

        } catch (ParseException | BadJOSEException e) {
            System.err.println("JWT validation failed: " + e.getMessage());
            simpleAuthOutput.failAuthentication();
        } catch (JOSEException e) {
            System.err.println("JWT processing error: " + e.getMessage());
            simpleAuthOutput.failAuthentication();
        }
    }
}
