package org.example;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

//PKCE ensures that only the client that created the codeVerifier can exchange the code for an access token
//Prevents malicious applications from intercepting the authorization code and using it to obtain tokens
public class PKCEUtils {

    //generates a cryptographic random string
    public static String generateCodeVerifier() {
        byte[] randomBytes = new byte[32];
        new SecureRandom().nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    //generates a SHA256 hash of the code verifier and encodes it in Base64 URL-safe format
    public static String generateCodeChallenge(String codeVerifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String generateAuthURL(String clientId, String redirectUri, String codeChallenge) {
        return String.format(
                "%s/realms/%s/protocol/openid-connect/auth?" +
                        "response_type=code&client_id=%s&redirect_uri=%s&scope=openid&code_challenge=%s" +
                        "&code_challenge_method=S256",
                Config.BASE_URL,
                Config.KEYCLOAK_REALM,
                clientId,
                redirectUri,
                codeChallenge
        );
    }


}
