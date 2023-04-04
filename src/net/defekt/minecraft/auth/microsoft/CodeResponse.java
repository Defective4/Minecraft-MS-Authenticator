package net.defekt.minecraft.auth.microsoft;

public class CodeResponse {
    private String device_code, user_code, verification_uri, message;
    private int expires_in, interval;

    public String getDevice_code() {
        return device_code;
    }

    public String getUser_code() {
        return user_code;
    }

    public String getVerification_uri() {
        return verification_uri;
    }

    public String getMessage() {
        return message;
    }

    public int getExpires_in() {
        return expires_in;
    }

    public int getInterval() {
        return interval < 0 ? 1 : interval;
    }
}