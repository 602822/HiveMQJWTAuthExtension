package org.example;

import com.hivemq.extension.sdk.api.ExtensionMain;
import com.hivemq.extension.sdk.api.annotations.NotNull;
import com.hivemq.extension.sdk.api.parameter.*;
import com.hivemq.extension.sdk.api.services.Services;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MyExtensionMain implements ExtensionMain {

    private static final @NotNull Logger log = LoggerFactory.getLogger(MyExtensionMain.class);


    @Override
    public void extensionStart(@NotNull ExtensionStartInput extensionStartInput, @NotNull ExtensionStartOutput extensionStartOutput) {

        try {
            registerAuthenticatorProvider();
            final ExtensionInformation extensionInformation = extensionStartInput.getExtensionInformation();
            log.info("Started: {}:{}", extensionInformation.getName(), extensionInformation.getVersion());
        } catch (Exception e) {
            log.error("Failed to start extension", e);
        }
    }

    private static void registerAuthenticatorProvider() {
        MyAuthenticatorProvider myAuthenticatorProvider = new MyAuthenticatorProvider(new MyAuthenticator());
        Services.securityRegistry().setAuthenticatorProvider(myAuthenticatorProvider);
        log.info("MyAuthenticatorProvider registered successfully.");
    }

    @Override
    public void extensionStop(@NotNull ExtensionStopInput extensionStopInput, @NotNull ExtensionStopOutput extensionStopOutput) {
        final ExtensionInformation extensionInformation = extensionStopInput.getExtensionInformation();
        log.info("Stopped: {}:{}", extensionInformation.getName(), extensionInformation.getVersion());

    }
}
