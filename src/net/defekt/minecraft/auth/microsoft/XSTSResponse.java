package net.defekt.minecraft.auth.microsoft;

public class XSTSResponse {
    String token;
    String userhash;

    public XSTSResponse(String token, String userhash) {
        super();
        this.token = token;
        this.userhash = userhash;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getUserhash() {
        return userhash;
    }

    public void setUserhash(String userhash) {
        this.userhash = userhash;
    }

}