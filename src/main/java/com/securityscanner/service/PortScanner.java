package com.securityscanner.service;

import com.securityscanner.model.SecurityIssue;
import javafx.concurrent.Task;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Service for scanning open ports on a target host
 */
public class PortScanner extends Task<List<SecurityIssue>> {
    private final String host;
    private final int startPort;
    private final int endPort;
    private final int timeout;
    private final int threadPoolSize;
    private List<Thread> threads; // Add this field to track worker threads
    
    // Well-known services mapped to ports
    private static final Map<Integer, String> PORT_SERVICES = new HashMap<>();
    static {
        PORT_SERVICES.put(21, "FTP");
        PORT_SERVICES.put(22, "SSH");
        PORT_SERVICES.put(23, "Telnet");
        PORT_SERVICES.put(25, "SMTP");
        PORT_SERVICES.put(53, "DNS");
        PORT_SERVICES.put(80, "HTTP");
        PORT_SERVICES.put(110, "POP3");
        PORT_SERVICES.put(143, "IMAP");
        PORT_SERVICES.put(443, "HTTPS");
        PORT_SERVICES.put(1433, "MSSQL");
        PORT_SERVICES.put(3306, "MySQL");
        PORT_SERVICES.put(3389, "RDP");
        PORT_SERVICES.put(5432, "PostgreSQL");
        PORT_SERVICES.put(8080, "HTTP-Alternate");
        PORT_SERVICES.put(8443, "HTTPS-Alternate");
    }
    
    public PortScanner(String host, int startPort, int endPort, int timeout, int threadPoolSize) {
        this.host = host;
        this.startPort = startPort;
        this.endPort = endPort;
        this.timeout = timeout;
        this.threadPoolSize = threadPoolSize;
        this.threads = new ArrayList<>(); // Initialize threads list
    }
    
    /**
     * Get the list of worker threads used by this scanner
     * @return List of worker threads
     */
    public List<Thread> getWorkerThreads() {
        return threads;
    }
    
    @Override
    protected List<SecurityIssue> call() throws Exception {
        updateMessage("Starting port scan on " + host);
        List<SecurityIssue> issues = Collections.synchronizedList(new ArrayList<>());
        List<Integer> openPorts = Collections.synchronizedList(new ArrayList<>());
        
        int totalPorts = endPort - startPort + 1;
        AtomicInteger scannedPorts = new AtomicInteger(0);
        
        // Create threads for port scanning
        threads = new ArrayList<>(); // Reset in case this task is reused
        int portsPerThread = totalPorts / threadPoolSize;
        int remainder = totalPorts % threadPoolSize;
        
        for (int i = 0; i < threadPoolSize; i++) {
            int threadStartPort = startPort + (i * portsPerThread);
            int threadEndPort = threadStartPort + portsPerThread - 1;
            
            // Distribute remaining ports
            if (i == threadPoolSize - 1) {
                threadEndPort += remainder;
            }
            
            final int finalThreadStartPort = threadStartPort;
            final int finalThreadEndPort = threadEndPort;
            
            Thread thread = new Thread(() -> {
                for (int port = finalThreadStartPort; port <= finalThreadEndPort; port++) {
                    // Check if task has been cancelled
                    if (isCancelled()) {
                        break;
                    }
                    
                    try (Socket socket = new Socket()) {
                        socket.connect(new InetSocketAddress(host, port), timeout);
                        openPorts.add(port);
                        
                        String serviceName = PORT_SERVICES.getOrDefault(port, "Unknown");
                        updateMessage("Found open port: " + port + " (" + serviceName + ")");
                    } catch (IOException e) {
                        // Port is closed or unreachable - this is expected
                    } catch (Exception e) {
                        // Handle any other exceptions that might occur
                        updateMessage("Error scanning port " + port + ": " + e.getMessage());
                    }
                    
                    // Update progress
                    int completed = scannedPorts.incrementAndGet();
                    updateProgress(completed, totalPorts);
                    
                    // Check for cancellation again after potentially long operation
                    if (isCancelled()) {
                        break;
                    }
                }
            });
            
            thread.setDaemon(true); // Make sure threads don't prevent JVM shutdown
            threads.add(thread);
            thread.start();
        }
        
        // Wait for all threads to complete
        for (Thread thread : threads) {
            try {
                thread.join();
            } catch (InterruptedException e) {
                // If we're interrupted, propagate the interrupt
                Thread.currentThread().interrupt();
                updateMessage("Port scan interrupted");
                return issues;
            }
        }
        
        // Process results
        if (isCancelled()) {
            updateMessage("Port scan cancelled");
            return issues;
        }
        
        // Sort the open ports for better display
        Collections.sort(openPorts);
        
        // Create security issues for open ports
        for (int port : openPorts) {
            String serviceName = PORT_SERVICES.getOrDefault(port, "Unknown");
            String severity = (port < 1024) ? "MEDIUM" : "LOW";
            
            SecurityIssue issue = new SecurityIssue(
                "Open Port: " + port + " (" + serviceName + ")",
                severity,
                "Port " + port + " is open and running " + serviceName + " service, which could expose the system to potential attacks if not properly secured.",
                "Verify if this port needs to be open and secure it appropriately, or close it if unnecessary."
            );
            
            issues.add(issue);
        }
        
        updateMessage("Port scan completed. Found " + openPorts.size() + " open ports.");
        
        return issues;
    }
    
    @Override
    protected void cancelled() {
        super.cancelled();
        // Make sure to interrupt all worker threads
        for (Thread thread : threads) {
            thread.interrupt();
        }
        updateMessage("Port scan cancelled by user");
    }
}