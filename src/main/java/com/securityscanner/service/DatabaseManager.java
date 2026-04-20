package com.securityscanner.service;

import com.securityscanner.model.SecurityIssue;
import java.sql.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Manages database operations for storing and retrieving scan results
 */
public class DatabaseManager {
    private static final String DB_URL = "jdbc:h2:./securityscanner";
    private static final String USER = "sa";
    private static final String PASSWORD = "";
    
    private static DatabaseManager instance;
    private Connection connection;
    
    private DatabaseManager() {
        initialize();
    }
    
    public static synchronized DatabaseManager getInstance() {
        if (instance == null) {
            instance = new DatabaseManager();
        }
        return instance;
    }
    
    /**
     * Initialize the database and create necessary tables if they don't exist
     */
    private void initialize() {
        try {
            // Load the H2 database driver
            Class.forName("org.h2.Driver");
            
            // Create a connection
            connection = DriverManager.getConnection(DB_URL, USER, PASSWORD);
            
            // Create tables
            createTables();
            
            System.out.println("Database initialized successfully");
        } catch (ClassNotFoundException | SQLException e) {
            System.err.println("Error initializing database: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Create necessary tables if they don't exist
     */
    private void createTables() throws SQLException {
        Statement statement = connection.createStatement();
        
        // Create SCAN_SESSIONS table
        statement.execute(
            "CREATE TABLE IF NOT EXISTS SCAN_SESSIONS (" +
            "   ID BIGINT AUTO_INCREMENT PRIMARY KEY, " +
            "   TARGET VARCHAR(255) NOT NULL, " +
            "   SCAN_TYPE VARCHAR(50) NOT NULL, " +
            "   SCAN_DATE TIMESTAMP NOT NULL " +
            ")"
        );
        
        // Create SECURITY_ISSUES table
        statement.execute(
            "CREATE TABLE IF NOT EXISTS SECURITY_ISSUES (" +
            "   ID BIGINT AUTO_INCREMENT PRIMARY KEY, " +
            "   SESSION_ID BIGINT NOT NULL, " +
            "   TITLE VARCHAR(255) NOT NULL, " +
            "   SEVERITY VARCHAR(20) NOT NULL, " +
            "   DESCRIPTION CLOB, " +
            "   RECOMMENDATION CLOB, " +
            "   DISCOVERY_DATE TIMESTAMP NOT NULL, " +
            "   FOREIGN KEY (SESSION_ID) REFERENCES SCAN_SESSIONS(ID) " +
            ")"
        );
        
        statement.close();
    }
    
    /**
     * Save a list of security issues to the database
     * @param target The scanned target (URL or IP)
     * @param scanType The type of scan performed
     * @param issues The list of security issues found
     * @return The number of issues saved
     */
    public int saveIssues(String target, String scanType, List<SecurityIssue> issues) {
        if (issues == null || issues.isEmpty()) {
            return 0;
        }
        
        try {
            // Start a transaction
            connection.setAutoCommit(false);
            
            // Create a new scan session
            PreparedStatement sessionStmt = connection.prepareStatement(
                "INSERT INTO SCAN_SESSIONS (TARGET, SCAN_TYPE, SCAN_DATE) VALUES (?, ?, ?)",
                Statement.RETURN_GENERATED_KEYS
            );
            
            sessionStmt.setString(1, target);
            sessionStmt.setString(2, scanType);
            sessionStmt.setTimestamp(3, Timestamp.valueOf(LocalDateTime.now()));
            sessionStmt.executeUpdate();
            
            // Get the generated session ID
            ResultSet generatedKeys = sessionStmt.getGeneratedKeys();
            long sessionId = -1;
            if (generatedKeys.next()) {
                sessionId = generatedKeys.getLong(1);
            } else {
                connection.rollback();
                return 0;
            }
            
            // Insert security issues
            PreparedStatement issueStmt = connection.prepareStatement(
                "INSERT INTO SECURITY_ISSUES " +
                "(SESSION_ID, TITLE, SEVERITY, DESCRIPTION, RECOMMENDATION, DISCOVERY_DATE) " +
                "VALUES (?, ?, ?, ?, ?, ?)"
            );
            
            for (SecurityIssue issue : issues) {
                issueStmt.setLong(1, sessionId);
                issueStmt.setString(2, issue.getTitle());
                issueStmt.setString(3, issue.getSeverity());
                issueStmt.setString(4, issue.getDescription());
                issueStmt.setString(5, issue.getRecommendation());
                issueStmt.setTimestamp(6, Timestamp.valueOf(issue.getDiscoveryDate()));
                issueStmt.addBatch();
            }
            
            int[] results = issueStmt.executeBatch();
            
            // Commit the transaction
            connection.commit();
            
            // Count the number of successful inserts
            int savedCount = 0;
            for (int result : results) {
                if (result > 0) {
                    savedCount++;
                }
            }
            
            return savedCount;
            
        } catch (SQLException e) {
            try {
                // Rollback on error
                connection.rollback();
            } catch (SQLException rollbackEx) {
                System.err.println("Error rolling back transaction: " + rollbackEx.getMessage());
            }
            
            System.err.println("Error saving issues to database: " + e.getMessage());
            e.printStackTrace();
            return 0;
        } finally {
            try {
                connection.setAutoCommit(true);
            } catch (SQLException e) {
                System.err.println("Error resetting auto-commit: " + e.getMessage());
            }
        }
    }
    
    /**
     * Retrieves all scan sessions from the database
     * @return List of scan sessions
     */
    public List<ScanSession> getScanSessions() {
        List<ScanSession> sessions = new ArrayList<>();
        
        try {
            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery(
                "SELECT ID, TARGET, SCAN_TYPE, SCAN_DATE FROM SCAN_SESSIONS ORDER BY SCAN_DATE DESC"
            );
            
            while (rs.next()) {
                ScanSession session = new ScanSession(
                    rs.getLong("ID"),
                    rs.getString("TARGET"),
                    rs.getString("SCAN_TYPE"),
                    rs.getTimestamp("SCAN_DATE").toLocalDateTime()
                );
                sessions.add(session);
            }
            
        } catch (SQLException e) {
            System.err.println("Error retrieving scan sessions: " + e.getMessage());
        }
        
        return sessions;
    }
    
    /**
     * Retrieves all security issues for a specific scan session
     * @param sessionId The ID of the scan session
     * @return List of security issues
     */
    public List<SecurityIssue> getIssuesBySessionId(long sessionId) {
        List<SecurityIssue> issues = new ArrayList<>();
        
        try {
            PreparedStatement stmt = connection.prepareStatement(
                "SELECT ID, TITLE, SEVERITY, DESCRIPTION, RECOMMENDATION, DISCOVERY_DATE " +
                "FROM SECURITY_ISSUES WHERE SESSION_ID = ?"
            );
            
            stmt.setLong(1, sessionId);
            ResultSet rs = stmt.executeQuery();
            
            while (rs.next()) {
                SecurityIssue issue = new SecurityIssue(
                    rs.getLong("ID"),
                    rs.getString("TITLE"),
                    rs.getString("SEVERITY"),
                    rs.getString("DESCRIPTION"),
                    rs.getString("RECOMMENDATION"),
                    rs.getTimestamp("DISCOVERY_DATE").toLocalDateTime()
                );
                issues.add(issue);
            }
            
        } catch (SQLException e) {
            System.err.println("Error retrieving issues for session: " + e.getMessage());
        }
        
        return issues;
    }
    
    /**
     * Close the database connection
     */
    public void close() {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
                System.out.println("Database connection closed");
            }
        } catch (SQLException e) {
            System.err.println("Error closing database connection: " + e.getMessage());
        }
    }
    
    /**
     * Inner class to represent a scan session
     */
    public static class ScanSession {
        private final long id;
        private final String target;
        private final String scanType;
        private final LocalDateTime scanDate;
        
        public ScanSession(long id, String target, String scanType, LocalDateTime scanDate) {
            this.id = id;
            this.target = target;
            this.scanType = scanType;
            this.scanDate = scanDate;
        }
        
        public long getId() {
            return id;
        }
        
        public String getTarget() {
            return target;
        }
        
        public String getScanType() {
            return scanType;
        }
        
        public LocalDateTime getScanDate() {
            return scanDate;
        }
        
        @Override
        public String toString() {
            return scanDate + " - " + scanType + " scan of " + target;
        }
    }
}