package org.example;

public record TokenResponse(String accessToken, String refreshToken, long expiresIn) {

}
