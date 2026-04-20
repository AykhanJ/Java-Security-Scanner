package com.securityscanner.service;

import com.securityscanner.model.SecurityIssue;
import javafx.concurrent.Task;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Service for scanning SSL/TLS configurations and certificates
 */
public class SSLScanner extends Task<List<SecurityIssue>> {
    private String hostName;
    private int port;
    private final int timeout;
    
    // List of weak/outdated SSL/TLS protocols
    private static final Set<String> WEAK_PROTOCOLS = new HashSet<>(Arrays.asList(
        "SSLv2", "SSLv3", "TLSv1", "TLSv1.1"
    ));
    
    // List of weak cipher suites (partial list)
    private static final Set<String> WEAK_CIPHERS = new HashSet<>(Arrays.asList(
        "TLS_RSA_WITH_RC4_128_SHA",
        "TLS_RSA_WITH_RC4_128_MD5",
        "TLS_RSA_WITH_DES_CBC_SHA",
        "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
        "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
        "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
        "TLS_DHE_RSA_WITH_DES_CBC_SHA",
        "TLS_DHE_DSS_WITH_DES_CBC_SHA",
        "SSL_RSA_WITH_DES_CBC_SHA",
        "SSL_DHE_RSA_WITH_DES_CBC_SHA",
        "SSL_DHE_DSS_WITH_DES_CBC_SHA"
    ));
    
    public SSLScanner(String urlString, int timeout) {
        this.timeout = timeout;
        
        try {
            // Parse the URL to extract hostname and port
            URL url = new URL(urlString.startsWith("http") ? urlString : "https://" + urlString);
            this.hostName = url.getHost();
            this.port = url.getPort() != -1 ? url.getPort() : 443;
        } catch (Exception e) {
            // Handle malformed URLs
            this.hostName = urlString;
            this.port = 443;
        }
    }
    
    @Override
    protected List<SecurityIssue> call() throws Exception {
        updateMessage("Starting SSL/TLS scan on " + hostName + ":" + port);
        List<SecurityIssue> issues = new ArrayList<>();
        
        try {
            updateProgress(0.1, 1.0);
            
            // Create a trust manager that does not validate certificate chains
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) throws CertificateException { }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) throws CertificateException { }
                }
            };
            
            // Install the all-trusting trust manager
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
            SSLSocketFactory factory = sslContext.getSocketFactory();
            
            updateProgress(0.3, 1.0);
            
            // Create socket and connect
            try (SSLSocket socket = (SSLSocket) factory.createSocket(hostName, port)) {
                socket.setSoTimeout(timeout);
                updateMessage("Connecting to " + hostName + ":" + port);
                
                // Get supported protocols and ciphers
                String[] supportedProtocols = socket.getSupportedProtocols();
                String[] supportedCiphers = socket.getSupportedCipherSuites();
                
                // Check for weak protocols
                for (String protocol : supportedProtocols) {
                    if (WEAK_PROTOCOLS.contains(protocol)) {
                        issues.add(new SecurityIssue(
                            "Weak SSL/TLS Protocol Supported: " + protocol,
                            "HIGH",
                            "The server supports " + protocol + ", which is known to have security vulnerabilities.",
                            "Disable " + protocol + " on the server and use only TLSv1.2 or higher."
                        ));
                    }
                }
                
                // Check for weak cipher suites
                for (String cipher : supportedCiphers) {
                    if (WEAK_CIPHERS.contains(cipher)) {
                        issues.add(new SecurityIssue(
                            "Weak Cipher Suite Supported: " + cipher,
                            "MEDIUM",
                            "The server supports weak cipher suite " + cipher + " which may be vulnerable to attacks.",
                            "Disable this cipher suite and use only strong ciphers."
                        ));
                    }
                }
                
                updateProgress(0.6, 1.0);
                
                // Start handshake
                socket.startHandshake();
                
                // Get the server's certificate
                X509Certificate[] serverCerts = (X509Certificate[]) socket.getSession().getPeerCertificates();
                if (serverCerts.length > 0) {
                    X509Certificate serverCert = serverCerts[0];
                    
                    // Check certificate validity
                    try {
                        serverCert.checkValidity();
                    } catch (Exception e) {
                        issues.add(new SecurityIssue(
                            "Invalid SSL Certificate",
                            "HIGH",
                            "The SSL certificate is not valid: " + e.getMessage(),
                            "Install a valid SSL certificate from a trusted certificate authority."
                        ));
                    }
                    
                    // Check certificate expiration date
                    Date expirationDate = serverCert.getNotAfter();
                    LocalDateTime expiration = expirationDate.toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime();
                    LocalDateTime now = LocalDateTime.now();
                    LocalDateTime thirtyDaysLater = now.plusDays(30);
                    
                    if (expiration.isBefore(now)) {
                        issues.add(new SecurityIssue(
                            "Expired SSL Certificate",
                            "HIGH",
                            "The SSL certificate expired on " + expiration,
                            "Renew the SSL certificate immediately."
                        ));
                    } else if (expiration.isBefore(thirtyDaysLater)) {
                        issues.add(new SecurityIssue(
                            "Certificate Expiring Soon",
                            "MEDIUM",
                            "The SSL certificate will expire on " + expiration + " (in less than 30 days).",
                            "Renew the SSL certificate before it expires."
                        ));
                    }
                    
                    // Check certificate subject
                    String subject = serverCert.getSubjectX500Principal().getName();
                    updateMessage("Certificate subject: " + subject);
                }
            }
            
            if (issues.isEmpty()) {
                issues.add(new SecurityIssue(
                    "SSL/TLS Configuration",
                    "INFO",
                    "No immediate SSL/TLS issues were detected.",
                    "Continue to follow best practices for SSL/TLS configuration and keep certificates up to date."
                ));
            }
            
        } catch (IOException e) {
            updateMessage("Error during SSL/TLS scan: " + e.getMessage());
            issues.add(new SecurityIssue(
                "SSL/TLS Connection Failed",
                "HIGH",
                "Failed to establish a secure connection: " + e.getMessage(),
                "Verify that the server has SSL/TLS properly configured."
            ));
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            updateMessage("Error setting up SSL/TLS scanner: " + e.getMessage());
            issues.add(new SecurityIssue(
                "Scanner Configuration Error",
                "INFO",
                "Failed to initialize SSL/TLS scanner: " + e.getMessage(),
                "This is an internal error in the scanning tool."
            ));
        }
        
        updateProgress(1.0, 1.0);
        updateMessage("SSL/TLS scan completed. Found " + issues.size() + " issues.");
        
        return issues;
    }
}