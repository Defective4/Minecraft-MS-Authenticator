package net.defekt.minecraft.auth.microsoft;

public class OnlineProfile {
    private final String id, name, skinUrl;

    public OnlineProfile(String id, String name, String skinUrl) {
        super();
        this.id = id;
        this.name = name;
        this.skinUrl = skinUrl;
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getSkinUrl() {
        return skinUrl;
    }
}