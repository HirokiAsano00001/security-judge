// VULNERABILITY FIXTURE - for testing gitleaks / SAST detection
public class VulnConfig {
    private static final String DB_PASSWORD = "P@ssw0rd!Database123";
    private static final String API_KEY = "sk-test-abcdefghij1234567890";

    public static String getPassword() {
        return DB_PASSWORD;
    }
}
