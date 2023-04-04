package net.defekt.minecraft.auth.microsoft;

public class MinecraftAuthResponse {
    private String username, access_token, token_type;

    public String getUsername() {
        return username;
    }

    public String getAccess_token() {
        return access_token;
    }

    public String getToken_type() {
        return token_type;
    }
}