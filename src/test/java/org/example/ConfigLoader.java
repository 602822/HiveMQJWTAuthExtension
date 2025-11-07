package org.example;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

//Used to load sensitive data from a properties file
public class ConfigLoader {
    public static Properties load() throws IOException {
        Properties props = new Properties();
        try (FileInputStream fis = new FileInputStream("config.properties")) {
            props.load(fis);
        }
        return props;
    }
}
