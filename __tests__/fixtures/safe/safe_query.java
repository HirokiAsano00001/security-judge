// SAFE FIXTURE - parameterized query (no SQL injection)
import java.sql.PreparedStatement;
import java.sql.Connection;

public class SafeUserRepository {
    public User findByEmail(Connection conn, String email) throws Exception {
        String sql = "SELECT * FROM users WHERE email = ?";
        PreparedStatement stmt = conn.prepareStatement(sql);
        stmt.setString(1, email);
        return mapResultSet(stmt.executeQuery());
    }

    private User mapResultSet(java.sql.ResultSet rs) throws Exception {
        return new User(rs.getString("email"));
    }
}
