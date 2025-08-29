package org.example;

import com.hivemq.extension.sdk.api.annotations.NotNull;
import com.hivemq.extension.sdk.api.auth.SimpleAuthenticator;
import com.hivemq.extension.sdk.api.auth.parameter.SimpleAuthInput;
import com.hivemq.extension.sdk.api.auth.parameter.SimpleAuthOutput;
import com.hivemq.extension.sdk.api.packets.connect.ConnectPacket;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public class MyAuthenticator implements SimpleAuthenticator {
    @Override
    public void onConnect(@NotNull SimpleAuthInput simpleAuthInput, @NotNull SimpleAuthOutput simpleAuthOutput) {

        ConnectPacket connectPacket = simpleAuthInput.getConnectPacket();

        if(connectPacket.getUserName().isEmpty() || connectPacket.getPassword().isEmpty()){
            simpleAuthOutput.failAuthentication();
        }
        String username = connectPacket.getUserName().get();
        String password = StandardCharsets.UTF_8.decode(connectPacket.getPassword().get()).toString();
        if(username.equals("user") && password.equals("password")){  // temporary hardcoded username and password
            simpleAuthOutput.authenticateSuccessfully();
        } else {
            simpleAuthOutput.failAuthentication();
        }



    }
}
