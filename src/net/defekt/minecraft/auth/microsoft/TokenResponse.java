package net.defekt.minecraft.auth.microsoft;

public class TokenResponse {
    private String token_type, scope, access_token, refresh_token, id_token;
    private int expires_in;

    public String getToken_type() {
        return token_type;
    }

    public String getScope() {
        return scope;
    }

    public String getAccess_token() {
        return access_token;
    }

    public String getRefresh_token() {
        return refresh_token;
    }

    public String getId_token() {
        return id_token;
    }

    public int getExpires_in() {
        return expires_in;
    }
}