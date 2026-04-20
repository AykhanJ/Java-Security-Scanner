package com.securityscanner.service;

import com.securityscanner.model.SecurityIssue;
import javafx.concurrent.Task;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Service for scanning HTTP security headers
 */
public class HeaderScanner extends Task<List<SecurityIssue>> {
    private final String urlString;
    private final int timeout;
    
    // Essential security headers and their descriptions
    private static final Map<String, String[]> SECURITY_HEADERS = new HashMap<>();
    static {
        // Format: Header name, [Description, Severity]
        SECURITY_HEADERS.put("Strict-Transport-Security", new String[] {
            "Protects against protocol downgrade attacks and cookie hijacking by enforcing HTTPS connections",
            "HIGH"
        });
        SECURITY_HEADERS.put("Content-Security-Policy", new String[] {
            "Prevents Cross-Site Scripting (XSS) attacks by specifying valid content sources",
            "HIGH"
        });
        SECURITY_HEADERS.put("X-Content-Type-Options", new String[] {
            "Prevents MIME sniffing vulnerabilities by ensuring browsers respect the declared content type",
            "MEDIUM"
        });
        SECURITY_HEADERS.put("X-Frame-Options", new String[] {
            "Protects against clickjacking attacks by controlling whether the page can be embedded in frames",
            "MEDIUM"
        });
        SECURITY_HEADERS.put("X-XSS-Protection", new String[] {
            "Enables browser's built-in XSS filtering capabilities",
            "MEDIUM"
        });
        SECURITY_HEADERS.put("Referrer-Policy", new String[] {
            "Controls how much referrer information should be included with requests",
            "LOW"
        });
        SECURITY_HEADERS.put("Permissions-Policy", new String[] {
            "Restricts which browser features and APIs can be used in the page",
            "MEDIUM"
        });
        SECURITY_HEADERS.put("Cache-Control", new String[] {
            "Controls caching of sensitive content by browsers and proxies",
            "LOW"
        });
    }
    
    public HeaderScanner(String urlString, int timeout) {
        // Add protocol if missing
        if (!urlString.startsWith("http://") && !urlString.startsWith("https://")) {
            urlString = "https://" + urlString;
        }
        this.urlString = urlString;
        this.timeout = timeout;
    }
    
    @Override
    protected List<SecurityIssue> call() throws Exception {
        updateMessage("Starting HTTP header scan on " + urlString);
        List<SecurityIssue> issues = new ArrayList<>();
        
        try {
            updateProgress(0.1, 1.0);
            URL url = new URL(urlString);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(timeout);
            connection.setReadTimeout(timeout);
            
            // Set some request headers to mimic a real browser
            connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
            
            updateProgress(0.3, 1.0);
            
            // Connect to the server and get response code
            int responseCode = connection.getResponseCode();
            updateMessage("Got response code: " + responseCode);
            
            updateProgress(0.5, 1.0);
            
            // Check if using HTTPS
            if (!urlString.startsWith("https://")) {
                issues.add(new SecurityIssue(
                    "Non-HTTPS Connection",
                    "HIGH",
                    "The website is not using HTTPS, which can expose data to interception during transmission.",
                    "Implement HTTPS with a valid certificate for all website traffic."
                ));
            }
            
            // Check all security headers
            for (Map.Entry<String, String[]> entry : SECURITY_HEADERS.entrySet()) {
                String headerName = entry.getKey();
                String headerDescription = entry.getValue()[0];
                String severity = entry.getValue()[1];
                
                String headerValue = connection.getHeaderField(headerName);
                if (headerValue == null || headerValue.isEmpty()) {
                    issues.add(new SecurityIssue(
                        "Missing " + headerName + " Header",
                        severity,
                        "The " + headerName + " header is missing. " + headerDescription + ".",
                        "Implement the " + headerName + " header with appropriate values to enhance security."
                    ));
                } else {
                    updateMessage("Found header: " + headerName);
                }
            }
            
            // Check for Server header version disclosure
            String serverHeader = connection.getHeaderField("Server");
            if (serverHeader != null && !serverHeader.isEmpty() && serverHeader.matches(".*[0-9].*")) {
                issues.add(new SecurityIssue(
                    "Server Version Disclosure",
                    "MEDIUM",
                    "The server is revealing version information: " + serverHeader + ", which can help attackers identify vulnerable server versions.",
                    "Configure the server to hide version information in the Server header."
                ));
            }
            
            // Check for X-Powered-By header
            String poweredByHeader = connection.getHeaderField("X-Powered-By");
            if (poweredByHeader != null && !poweredByHeader.isEmpty()) {
                issues.add(new SecurityIssue(
                    "Technology Disclosure",
                    "LOW",
                    "The X-Powered-By header reveals server technology: " + poweredByHeader + ", which can help attackers target specific vulnerabilities.",
                    "Remove or modify the X-Powered-By header to avoid disclosing unnecessary information."
                ));
            }
            
            connection.disconnect();
            
            updateProgress(1.0, 1.0);
            updateMessage("HTTP header scan completed. Found " + issues.size() + " security issues.");
            
        } catch (IOException e) {
            updateMessage("Error scanning URL: " + e.getMessage());
            issues.add(new SecurityIssue(
                "Connection Error",
                "INFO",
                "Failed to connect to the server: " + e.getMessage(),
                "Verify the URL is correct and the server is accessible."
            ));
        }
        
        return issues;
    }
}