package org.example;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.concurrent.CompletableFuture;

public class AuthServer {


    public static CompletableFuture<String> waitForAuthCode(int port) throws IOException {
        //Holds the authorization code once received (waits asynchronously for the user to authenticate without blocking the main thread)
        CompletableFuture<String> codeFuture = new CompletableFuture<>();

        //creates a http server that listens on port
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

        //the handler is triggered once the user redirects
        server.createContext("/callback", exchange -> {

            //Extracts the query parameters
            String query = exchange.getRequestURI().getQuery();

            //sends a response to the browser
            String responseText = "Authentication successful! You can close this window.";
            exchange.sendResponseHeaders(200, responseText.getBytes().length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(responseText.getBytes());
            }

            //extracts the authorization code from the query parameters
            if (query != null && query.contains("code=")) {
                String code = query.split("code=")[1].split("&")[0];
                codeFuture.complete(code);
            } else {
                codeFuture.completeExceptionally(new RuntimeException("Authorization code not found in the redirect URI."));
            }
            server.stop(0);
        });
        server.start();
        return codeFuture;
    }
}
