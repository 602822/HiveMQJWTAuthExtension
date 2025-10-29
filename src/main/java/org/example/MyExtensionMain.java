package org.example;

import com.hivemq.extension.sdk.api.ExtensionMain;
import com.hivemq.extension.sdk.api.annotations.NotNull;
import com.hivemq.extension.sdk.api.parameter.*;
import com.hivemq.extension.sdk.api.services.Services;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;

public class MyExtensionMain implements ExtensionMain {

    private static final @NotNull Logger log = LoggerFactory.getLogger(MyExtensionMain.class);


    @Override
    public void extensionStart(@NotNull ExtensionStartInput extensionStartInput, @NotNull ExtensionStartOutput extensionStartOutput) {

        final ExtensionInformation extensionInformation = extensionStartInput.getExtensionInformation();

        try {
            MyAuthenticatorProvider myAuthenticatorProvider = new MyAuthenticatorProvider();
            MyAuthorizerProvider myAuthorizerProvider = new MyAuthorizerProvider();
            Services.securityRegistry().setAuthenticatorProvider(myAuthenticatorProvider);
            Services.securityRegistry().setAuthorizerProvider(myAuthorizerProvider);

            log.info("MyAuthenticatorProvider registered successfully.");
            log.info("MyAuthorizerProvider registered successfully.");
            log.info("Started: {}:{}", extensionInformation.getName(), extensionInformation.getVersion());
        } catch (MalformedURLException e) {
            log.error("Invalid JWKS URL, extension startup aborted.", e);
            extensionStartOutput.preventExtensionStartup("Invalid JWKS URL: " + e.getMessage());

        } catch (Exception e) {
            log.error("Unexpected error during extension startup", e);
            extensionStartOutput.preventExtensionStartup("Unexpected error: " + e.getMessage());
        }
    }


    @Override
    public void extensionStop(@NotNull ExtensionStopInput extensionStopInput, @NotNull ExtensionStopOutput extensionStopOutput) {
        final ExtensionInformation extensionInformation = extensionStopInput.getExtensionInformation();
        log.info("Stopped: {}:{}", extensionInformation.getName(), extensionInformation.getVersion());

    }
}
