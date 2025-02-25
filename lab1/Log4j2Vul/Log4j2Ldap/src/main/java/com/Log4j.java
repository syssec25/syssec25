package com;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Log4j {
    private static final Logger LOGGER = LogManager.getLogger(Log4j.class);
    public static void main(String[] args) {
        //TODO: fill in the "" to trigger Log4j
        System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase", "true");
        LOGGER.error("");
    }
}
