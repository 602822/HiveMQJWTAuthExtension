
package org.example;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import org.json.JSONObject;

public class KeycloakAuthSubscriber {

    public KeycloakAuthSubscriber() {
    }

    public static TokenResponse getTokenUserPKCE(String code, String redirectUri, String clientId, String codeVerifier) throws IOException, InterruptedException {
        String urlString = "http://localhost:8080/realms/smartocean-testrealm/protocol/openid-connect/token";
        String data = "grant_type=authorization_code&code=" + code + "&redirect_uri=" + redirectUri + "&client_id=" + clientId + "&code_verifier=" + codeVerifier;
        return requestToken(urlString, data);
    }

    private static TokenResponse requestToken(String urlString, String data) throws IOException, InterruptedException {
        HttpClient httpClient = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder().uri(URI.create(urlString)).header("Content-Type", "application/x-www-form-urlencoded").POST(BodyPublishers.ofString(data)).build();
        HttpResponse<String> response = httpClient.send(request, BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            int var10002 = response.statusCode();
            throw new IOException("Failed to authenticate: " + var10002 + " " + (String)response.body());
        } else {
            JSONObject json = new JSONObject((String)response.body());
            String accessToken = json.getString("access_token");
            String refreshToken = json.getString("refresh_token");
            long expiresIn = json.getLong("expires_in");
            return new TokenResponse(accessToken, refreshToken, expiresIn);
        }
    }

}
