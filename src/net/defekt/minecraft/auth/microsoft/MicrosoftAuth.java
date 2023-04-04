package net.defekt.minecraft.auth.microsoft;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Timer;
import java.util.TimerTask;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

public class MicrosoftAuth {

    private static final String CLIENT_ID = "389b1b32-b5d5-43b2-bddc-84ce938d6737";

    private static HttpURLConnection openJson(String url) throws IOException {
        return open(url, "application/json", "application/json");
    }

    private static HttpURLConnection openWWW(String url) throws IOException {
        return open(url, "application/x-www-form-urlencoded", null);
    }

    private static HttpURLConnection open(String url, String type, String accept) throws IOException {
        HttpURLConnection con = (HttpURLConnection) new URL(url).openConnection();
        con.setDoOutput(true);
        con.setRequestMethod("POST");
        con.setRequestProperty("User-Agent", "Java");
        con.setRequestProperty("Content-Type", type);
        if (accept != null) con.setRequestProperty("Accept", accept);
        return con;
    }

    public static TokenResponse refreshToken(String refreshToken) throws IOException {
        HttpURLConnection con = openWWW("https://login.microsoftonline.com/consumers/oauth2/v2.0/token");
        OutputStream os = con.getOutputStream();
        os.write(("client_id=" + CLIENT_ID + "&grant_type=refresh_token&refresh_token=" + refreshToken).getBytes());
        os.close();
        int code = con.getResponseCode();
        if (code >= 400) {
            InputStreamReader reader = new InputStreamReader(con.getErrorStream());
            String error = new JsonParser().parse(reader).getAsJsonObject().get("error").getAsString();
            con.disconnect();
            throw new IOException(error);
        } else {
            InputStreamReader reader = new InputStreamReader(con.getInputStream());
            TokenResponse token = new Gson().fromJson(reader, TokenResponse.class);
            reader.close();
            con.disconnect();
            return token;
        }
    }

    public static void authenticateCode(CodeResponse response, TokenCallback callback) {
        Timer timer = new Timer(false);
        timer.scheduleAtFixedRate(new TimerTask() {

            @Override
            public void run() {
                try {
                    HttpURLConnection con = openWWW("https://login.microsoftonline.com/consumers/oauth2/v2.0/token");
                    OutputStream os = con.getOutputStream();
                    os.write(("grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=" + CLIENT_ID
                            + "&device_code=" + response.getDevice_code()).getBytes());
                    os.close();
                    int code = con.getResponseCode();
                    if (code >= 400) {
                        InputStreamReader reader = new InputStreamReader(con.getErrorStream());
                        String error = new JsonParser().parse(reader).getAsJsonObject().get("error").getAsString();
                        TokenErrorResponse resp = null;
                        if (error != null) {
                            resp = TokenErrorResponse.getForResponse(error);
                        }
                        if (resp == null || resp != TokenErrorResponse.PENDING) {
                            callback.errored(resp);
                            cancel();
                            timer.cancel();
                        }
                        reader.close();
                    } else {
                        InputStreamReader reader = new InputStreamReader(con.getInputStream());
                        TokenResponse token = new Gson().fromJson(reader, TokenResponse.class);
                        reader.close();
                        con.disconnect();

                        callback.authed(token);
                        cancel();
                        timer.cancel();
                    }
                } catch (Exception e) {
                    callback.exception(e);
                    cancel();
                    timer.cancel();
                }
            }
        }, response.getInterval() * 1000, response.getInterval() * 1000);
    }

    public static CodeResponse retrieveCode() throws IOException {
        HttpURLConnection con = openWWW("https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode");
        OutputStream os = con.getOutputStream();
        os.write(("client_id=" + CLIENT_ID + "&scope=" + URLEncoder.encode("XboxLive.signin offline_access", "utf-8"))
                .getBytes());
        os.close();

        CodeResponse resp = new Gson().fromJson(new InputStreamReader(con.getInputStream()), CodeResponse.class);
        con.disconnect();
        return resp;
    }

    public static XSTSResponse authXSTS(String xblToken) throws IOException {
        HttpURLConnection con = openJson("https://xsts.auth.xboxlive.com/xsts/authorize");
        OutputStream os = con.getOutputStream();

        JsonObject root = new JsonObject();
        JsonObject props = new JsonObject();
        JsonArray tokens = new JsonArray();

        tokens.add(new JsonPrimitive(xblToken));

        props.add("SandboxId", new JsonPrimitive("RETAIL"));
        props.add("UserTokens", tokens);

        root.add("Properties", props);
        root.add("RelyingParty", new JsonPrimitive("rp://api.minecraftservices.com/"));
        root.add("TokenType", new JsonPrimitive("JWT"));

        os.write(root.toString().getBytes());
        os.close();

        int code = con.getResponseCode();
        if (code >= 400) {
            if (code == 401) {
                String err = Long.toString(new JsonParser().parse(new InputStreamReader(con.getInputStream()))
                        .getAsJsonObject().get("XErr").getAsLong());
                String msg = null;
                switch (err) {
                    case "2148916233": {
                        msg = "Your account doesn't have a Xbox account. Please sign up for one to continue.";
                        break;
                    }
                    case "2148916235": {
                        msg = "Xbox Live is not available in your region. Sorry!";
                        break;
                    }
                    case "2148916237":
                    case "2148916236": {
                        msg = "Adult verification needed.";
                        break;
                    }
                    case "2148916238": {
                        msg = "You account is a child. It must be added to a family to continue.";
                        break;
                    }
                    default:
                        break;
                }
                if (msg != null) throw new IOException(msg);
            }
            con.disconnect();
            throw new IOException("The server returned error " + code + " while getting XSTS token");
        }

        JsonObject obj = new JsonParser().parse(new InputStreamReader(con.getInputStream())).getAsJsonObject();

        String token = obj.get("Token").getAsString();
        String userHash = obj.get("DisplayClaims").getAsJsonObject().get("xui").getAsJsonArray().get(0)
                .getAsJsonObject().get("uhs").getAsString();

        con.disconnect();
        if (token == null) throw new IOException("Server returned null XSTS token!");

        return new XSTSResponse(token, userHash);
    }

    public static String authXBL(TokenResponse resp) throws IOException {
        HttpURLConnection con = openJson("https://user.auth.xboxlive.com/user/authenticate");

        OutputStream os = con.getOutputStream();

        JsonObject root = new JsonObject();
        JsonObject props = new JsonObject();

        props.add("AuthMethod", new JsonPrimitive("RPS"));
        props.add("SiteName", new JsonPrimitive("user.auth.xboxlive.com"));
        props.add("RpsTicket", new JsonPrimitive("d=" + resp.getAccess_token()));

        root.add("Properties", props);
        root.add("RelyingParty", new JsonPrimitive("http://auth.xboxlive.com"));
        root.add("TokenType", new JsonPrimitive("JWT"));

        os.write(root.toString().getBytes());
        os.close();

        int code = con.getResponseCode();
        if (code >= 400) {
            con.disconnect();
            throw new IOException("The server returned error " + code + " while authenticating with XBox Live");
        }
        String token = new JsonParser().parse(new InputStreamReader(con.getInputStream())).getAsJsonObject()
                .get("Token").getAsString();
        con.disconnect();

        if (token == null) {
            con.disconnect();
            throw new IOException("XBox Live returned null token...?");
        }
        return token;
    }

    public static MinecraftAuthResponse authMinecraft(XSTSResponse xsts) throws IOException {
        HttpURLConnection con = openJson("https://api.minecraftservices.com/authentication/login_with_xbox");
        OutputStream os = con.getOutputStream();
        os.write(("{\"identityToken\": \"XBL3.0 x=" + xsts.userhash + ";" + xsts.token + "\"}").getBytes());
        os.close();

        int code = con.getResponseCode();
        InputStreamReader reader = new InputStreamReader(code >= 400 ? con.getErrorStream() : con.getInputStream());
        if (code >= 400) {
            String error = new JsonParser().parse(reader).getAsJsonObject().get("error").getAsString();
            con.disconnect();
            throw new IOException("Server returned an error " + code + ": " + error);
        } else {
            MinecraftAuthResponse resp = new Gson().fromJson(reader, MinecraftAuthResponse.class);
            con.disconnect();
            return resp;
        }
    }

    public static OnlineProfile getProfile(String authToken) throws IOException {
        HttpURLConnection con = (HttpURLConnection) new URL("https://api.minecraftservices.com/minecraft/profile")
                .openConnection();
        con.setRequestProperty("User-Agent", "Java");
        con.setRequestProperty("Authorization", "Bearer " + authToken);

        if (con.getResponseCode() >= 400)
            throw new IOException("Server returned " + con.getResponseCode() + " when retrieving game profile!");

        JsonObject obj = new JsonParser().parse(new InputStreamReader(con.getInputStream())).getAsJsonObject();
        con.disconnect();

        if (obj.has("id") && obj.has("name")) {
            String skin;
            JsonArray skins = obj.getAsJsonArray("skins");
            if (skins != null && skins.size() > 0)
                skin = skins.get(0).getAsJsonObject().get("url").getAsString();
            else
                skin = null;
            return new OnlineProfile(obj.get("id").getAsString(), obj.get("name").getAsString(), skin);
        } else {
            return null;
        }
    }

    public static boolean ownsGame(String authToken) throws IOException {
        HttpURLConnection con = (HttpURLConnection) new URL("https://api.minecraftservices.com/entitlements/mcstore")
                .openConnection();
        con.setRequestProperty("User-Agent", "Java");
        con.setRequestProperty("Authorization", "Bearer " + authToken);

        if (con.getResponseCode() >= 400)
            throw new IOException("Server returned " + con.getResponseCode() + " when checking game ownership!");

        boolean own = new JsonParser().parse(new InputStreamReader(con.getInputStream())).getAsJsonObject().get("items")
                .getAsJsonArray().size() > 0;

        return own;
    }
}
