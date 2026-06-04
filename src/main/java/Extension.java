import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class Extension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Multi-Intruder");
        api.logging().logToOutput("Intruder to run multiple request concurrently.....");

        api.userInterface().registerContextMenuItemsProvider(new MenuItems(api));

    }
}
