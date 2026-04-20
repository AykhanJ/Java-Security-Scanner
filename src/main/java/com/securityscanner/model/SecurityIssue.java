package com.securityscanner.model;

import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;
import java.time.LocalDateTime;

/**
 * Represents a security issue found during a scan
 */
public class SecurityIssue {
    private final StringProperty title;
    private final StringProperty severity;
    private final StringProperty description;
    private final StringProperty recommendation;
    private final LocalDateTime discoveryDate;
    private Long id;
    
    public SecurityIssue(String title, String severity, String description, String recommendation) {
        this.title = new SimpleStringProperty(title);
        this.severity = new SimpleStringProperty(severity);
        this.description = new SimpleStringProperty(description);
        this.recommendation = new SimpleStringProperty(recommendation);
        this.discoveryDate = LocalDateTime.now();
    }
    
    public SecurityIssue(Long id, String title, String severity, String description, String recommendation, LocalDateTime discoveryDate) {
        this.id = id;
        this.title = new SimpleStringProperty(title);
        this.severity = new SimpleStringProperty(severity);
        this.description = new SimpleStringProperty(description);
        this.recommendation = new SimpleStringProperty(recommendation);
        this.discoveryDate = discoveryDate;
    }
    
    // Getters and setters
    public String getTitle() {
        return title.get();
    }
    
    public StringProperty titleProperty() {
        return title;
    }
    
    public String getSeverity() {
        return severity.get();
    }
    
    public StringProperty severityProperty() {
        return severity;
    }
    
    public String getDescription() {
        return description.get();
    }
    
    public StringProperty descriptionProperty() {
        return description;
    }
    
    public String getRecommendation() {
        return recommendation.get();
    }
    
    public StringProperty recommendationProperty() {
        return recommendation;
    }
    
    public LocalDateTime getDiscoveryDate() {
        return discoveryDate;
    }
    
    public Long getId() {
        return id;
    }
    
    public void setId(Long id) {
        this.id = id;
    }
    
    @Override
    public String toString() {
        return "SecurityIssue{" +
                "title=" + getTitle() +
                ", severity=" + getSeverity() +
                ", discoveryDate=" + discoveryDate +
                '}';
    }
}