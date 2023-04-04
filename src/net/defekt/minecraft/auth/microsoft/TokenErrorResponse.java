package net.defekt.minecraft.auth.microsoft;

public enum TokenErrorResponse {
    PENDING("authorization_pending"), DECLINED("authorization_declined"), BAD_CODE("bad_verification_code"),
    EXPIRED("expired_token");

    private final String response;

    private TokenErrorResponse(String response) {
        this.response = response;
    }

    public static TokenErrorResponse getForResponse(String response) {
        for (TokenErrorResponse resp : values())
            if (resp.getResponse().equalsIgnoreCase(response)) return resp;
        return null;
    }

    public String getResponse() {
        return response;
    }
}