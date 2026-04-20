package com.securityscanner;

import com.securityscanner.model.SecurityIssue;
import com.securityscanner.service.DatabaseManager;
import com.securityscanner.service.HeaderScanner;
import com.securityscanner.service.PortScanner;
import com.securityscanner.service.SSLScanner;
import javafx.stage.FileChooser;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.concurrent.Task;
import javafx.concurrent.Worker;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.effect.DropShadow;
import javafx.scene.effect.Reflection;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.paint.CycleMethod;
import javafx.scene.paint.LinearGradient;
import javafx.scene.paint.Stop;
import javafx.scene.shape.Rectangle;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;
import javafx.scene.text.Text;
import javafx.stage.Stage;
import javafx.util.Duration;
import javafx.scene.control.ChoiceDialog;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Main application class for the Security Scanner GUI
 */

public class SecurityScannerApp extends Application {

    // UI Components
    private TextField targetField;
    private TextField portRangeField;
    private Label portRangeLabel;
    private List<Thread> workerThreads;
    private ComboBox<String> scanTypeComboBox;
    private Button scanButton;
    private ProgressBar progressBar;
    private TextArea logArea;
    private TableView<SecurityIssue> resultsTable;
    private ObservableList<SecurityIssue> issuesList = FXCollections.observableArrayList();
    
    // Default values
    private static final int DEFAULT_TIMEOUT = 2000; // 2 seconds
    private static final int DEFAULT_THREAD_POOL_SIZE = 10;
    
    // Database manager
    private DatabaseManager databaseManager;
    
    // Current scan target and type (for saving to database)
    private String currentTarget;
    private String currentScanType;
    
    // Colors for gradient background
    private static final Color GRADIENT_START = Color.rgb(51, 51, 153); // Deep blue
    private static final Color GRADIENT_END = Color.rgb(138, 43, 226);  // Purple

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("Security Scanner");
        
        // Set application icon
        // Note: Create a resources folder and add a shield.png icon
     // Set application icon (shield.png must live in src/main/resources/)
        URL iconUrl = getClass().getResource("/shield.png");
        if (iconUrl != null) {
            primaryStage.getIcons().add(new Image(iconUrl.toExternalForm()));
        } else {
            System.err.println("⚠️ shield.png not found on classpath");
        }
        
        // Initialize database manager
        databaseManager = DatabaseManager.getInstance();
        
        // Main layout container
        BorderPane root = new BorderPane();
        
        // Create the header
        VBox headerBox = createHeader();
        root.setTop(headerBox);
        
        // Create the main content area with gradient background
        BorderPane contentPane = new BorderPane();
        contentPane.setBackground(createGradientBackground());
        
        // Create the input form
        VBox inputForm = createInputForm();
        contentPane.setTop(inputForm);
        
        // Create the log area
        VBox logBox = createLogArea();
        contentPane.setCenter(logBox);
        
        // Create the results area
        VBox resultsArea = createResultsArea();
        contentPane.setBottom(resultsArea);
        
        root.setCenter(contentPane);
        
        // Set the scene
        Scene scene = new Scene(root, 1000, 800);
        
        // Add CSS styles
        //scene.getStylesheets().add(getClass().getResource("/resources/styles.css").toExternalForm());
        
        primaryStage.setScene(scene);
        primaryStage.show();
        
        // Add close handler
        primaryStage.setOnCloseRequest(e -> {
            databaseManager.close();
        });
    }

    /**
     * Creates a gradient background
     */
    private Background createGradientBackground() {
        LinearGradient gradient = new LinearGradient(
            0, 0, 1, 1, true, CycleMethod.NO_CYCLE,
            new Stop(0, GRADIENT_START),
            new Stop(1, GRADIENT_END)
        );
        
        return new Background(new BackgroundFill(gradient, CornerRadii.EMPTY, Insets.EMPTY));
    }

    /**
     * Creates the header with logo and title
     */
    private Button stopButton;
    private Thread currentThread;
    private Task<List<SecurityIssue>> currentTask;
    
    private VBox createHeader() {
        VBox headerBox = new VBox(10);
        headerBox.setPadding(new Insets(15));
        headerBox.setAlignment(Pos.CENTER);
        
        // Create a background with gradient
        LinearGradient gradient = new LinearGradient(
            0, 0, 1, 0, true, CycleMethod.NO_CYCLE,
            new Stop(0, Color.rgb(20, 20, 80)),
            new Stop(1, Color.rgb(60, 20, 120))
        );
        BackgroundFill backgroundFill = new BackgroundFill(gradient, CornerRadii.EMPTY, Insets.EMPTY);
        headerBox.setBackground(new Background(backgroundFill));
        
        // HBox for logo and text
        HBox headerContent = new HBox(20);
        headerContent.setAlignment(Pos.CENTER);
        
        // Logo (replace with actual logo path)
     // Logo (logo.png must live in src/main/resources/)
        URL logoUrl = getClass().getResource("/logo.png");
        if (logoUrl != null) {
            ImageView logoView = new ImageView(new Image(logoUrl.toExternalForm()));
            logoView.setFitHeight(50);
            logoView.setFitWidth(50);
            logoView.setPreserveRatio(true);
            Reflection reflection = new Reflection();
            reflection.setFraction(0.3);
            logoView.setEffect(reflection);
            headerContent.getChildren().add(logoView);
        } else {
            System.err.println("⚠️ logo.png not found on classpath");
            // fallback placeholder…
            Rectangle placeholder = new Rectangle(50, 50, Color.LIGHTBLUE);
            DropShadow dropShadow = new DropShadow();
            dropShadow.setColor(Color.WHITE);
            dropShadow.setRadius(5);
            placeholder.setEffect(dropShadow);
            headerContent.getChildren().add(placeholder);
        }
        
        // Title and description
        VBox titleBox = new VBox(5);
        titleBox.setAlignment(Pos.CENTER_LEFT);
        
        Text titleText = new Text("Security Scanner");
        titleText.setFont(Font.font("Segoe UI", FontWeight.BOLD, 28));
        titleText.setFill(Color.WHITE);
        
        // Add drop shadow to title
        DropShadow dropShadow = new DropShadow();
        dropShadow.setColor(Color.BLACK);
        dropShadow.setRadius(3);
        dropShadow.setOffsetX(2);
        dropShadow.setOffsetY(2);
        titleText.setEffect(dropShadow);
        
        Text descriptionText = new Text("Scan web applications and network hosts for common security vulnerabilities");
        descriptionText.setFont(Font.font("Segoe UI", FontWeight.NORMAL, 14));
        descriptionText.setFill(Color.LIGHTGRAY);
        
        titleBox.getChildren().addAll(titleText, descriptionText);
        headerContent.getChildren().add(titleBox);
        
        // Create menu bar
        MenuBar menuBar = new MenuBar();
        menuBar.setStyle("-fx-background-color: white;");
        
        Menu fileMenu = new Menu("File");
        MenuItem historyItem = new MenuItem("View History");
        historyItem.setOnAction(e -> showHistoryDialog());
        MenuItem exportItem = new MenuItem("Export Results");
        exportItem.setOnAction(e -> exportResults());
        MenuItem exitItem = new MenuItem("Exit");
        exitItem.setOnAction(e -> {
            databaseManager.close();
            Platform.exit();
        });
        fileMenu.getItems().addAll(historyItem, exportItem, new SeparatorMenuItem(), exitItem);
        
        Menu helpMenu = new Menu("Help");
        MenuItem aboutItem = new MenuItem("About");
        aboutItem.setOnAction(e -> showAboutDialog());
        helpMenu.getItems().add(aboutItem);
        
        menuBar.getMenus().addAll(fileMenu, helpMenu);
        
        headerBox.getChildren().addAll(menuBar, headerContent);
        return headerBox;
    }

    /**
     * Creates the input form for scan configuration
     */
    private VBox createInputForm() {
        VBox vbox = new VBox(15);
        vbox.setPadding(new Insets(20));
        vbox.setAlignment(Pos.CENTER);
        
        // Create glass panel effect
        vbox.setStyle("-fx-background-color: rgba(255, 255, 255, 0.2); " +
                      "-fx-background-radius: 10; " +
                      "-fx-effect: dropshadow(three-pass-box, rgba(0,0,0,0.6), 10, 0, 0, 0);");
        
        Label formTitle = new Label("Scan Configuration");
        formTitle.setFont(Font.font("Segoe UI", FontWeight.BOLD, 18));
        formTitle.setTextFill(Color.WHITE);
        
        // Create input grid
        GridPane grid = new GridPane();
        grid.setHgap(20);
        grid.setVgap(15);
        grid.setAlignment(Pos.CENTER);
        
        // Target URL/IP input
        Label targetLabel = new Label("Target URL or IP:");
        targetLabel.setTextFill(Color.WHITE);
        targetLabel.setFont(Font.font("Segoe UI", 14));
        
        targetField = new TextField();
        targetField.setPromptText("e.g., example.com or 192.168.1.1");
        targetField.setPrefWidth(300);
        targetField.setStyle("-fx-background-color: rgba(255, 255, 255, 0.9); " +
                             "-fx-background-radius: 5; " +
                             "-fx-font-size: 14px;");
        
        grid.add(targetLabel, 0, 0);
        grid.add(targetField, 1, 0);
        
        // Port range input
        portRangeLabel = new Label("Port Range:");
        portRangeLabel.setTextFill(Color.WHITE);
        portRangeLabel.setFont(Font.font("Segoe UI", 14));
        
        portRangeField = new TextField("1-1000");
        portRangeField.setPromptText("e.g., 1-1000");
        portRangeField.setStyle("-fx-background-color: rgba(255, 255, 255, 0.9); " +
                                "-fx-background-radius: 5; " +
                                "-fx-font-size: 14px;");
        
        grid.add(portRangeLabel, 0, 1);
        grid.add(portRangeField, 1, 1);
        
        // Scan type selection
        Label scanTypeLabel = new Label("Scan Type:");
        scanTypeLabel.setTextFill(Color.WHITE);
        scanTypeLabel.setFont(Font.font("Segoe UI", 14));
        
        scanTypeComboBox = new ComboBox<>();
        scanTypeComboBox.getItems().addAll(
            "Port Scan",
            "HTTP Security Headers",
            "SSL/TLS Certificate"
        );
        scanTypeComboBox.setValue("Port Scan");
        scanTypeComboBox.setStyle("-fx-background-color: rgba(255, 255, 255, 0.9); " +
                                  "-fx-background-radius: 5; " +
                                  "-fx-font-size: 14px;");
        
        // Port range visibility based on scan type
        scanTypeComboBox.valueProperty().addListener((obs, oldVal, newVal) -> {
            boolean isPortScan = "Port Scan".equals(newVal);
            portRangeLabel.setVisible(isPortScan);
            portRangeField.setVisible(isPortScan);
        });
        
        grid.add(scanTypeLabel, 0, 2);
        grid.add(scanTypeComboBox, 1, 2);
        
        // Scan button and progress bar
        HBox controlBox = new HBox(15);
        controlBox.setAlignment(Pos.CENTER);
        
        scanButton = new Button("Start Scan");
        scanButton.setOnAction(e -> performScan());
        scanButton.setStyle("-fx-background-color: linear-gradient(to bottom, #4e54c8, #8f94fb); " +
                            "-fx-text-fill: white; " +
                            "-fx-font-size: 14px; " +
                            "-fx-font-weight: bold; " +
                            "-fx-padding: 10 20; " +
                            "-fx-background-radius: 5;");
        stopButton = new Button("Stop Scan");
        stopButton.setDisable(true);  // disabled until a scan starts
        stopButton.setStyle(
            "-fx-background-color: linear-gradient(to bottom, #e74c3c, #c0392b);" +
            "-fx-text-fill: white; -fx-font-size: 14px; -fx-font-weight: bold;" +
            "-fx-padding: 10 20; -fx-background-radius: 5;"
        );
        
        // Add hover effect to button
        scanButton.setOnMouseEntered(e -> 
            scanButton.setStyle("-fx-background-color: linear-gradient(to bottom, #5c62d6, #9da2ff); " +
                                "-fx-text-fill: white; " +
                                "-fx-font-size: 14px; " +
                                "-fx-font-weight: bold; " +
                                "-fx-padding: 10 20; " +
                                "-fx-background-radius: 5;"));
        
        scanButton.setOnMouseExited(e -> 
            scanButton.setStyle("-fx-background-color: linear-gradient(to bottom, #4e54c8, #8f94fb); " +
                                "-fx-text-fill: white; " +
                                "-fx-font-size: 14px; " +
                                "-fx-font-weight: bold; " +
                                "-fx-padding: 10 20; " +
                                "-fx-background-radius: 5;"));
        
        stopButton.setOnAction(e -> {
            // 1) Cancel the JavaFX Task
            if (currentTask != null) {
                currentTask.cancel();
            }
            
            // 2) Interrupt the main worker thread
            if (currentThread != null) {
                currentThread.interrupt();
            }
            
            // 3) Interrupt any PortScanner threads
            if (workerThreads != null) {
                for (Thread thread : workerThreads) {
                    if (thread != null && thread.isAlive()) {
                        thread.interrupt();
                    }
                }
            }

            // 4) Reset everything in the UI
            scanButton.setDisable(false);
            stopButton.setDisable(true);
            progressBar.setVisible(false);
            progressBar.setProgress(0);
            logMessage("Scan stopped by user");
            
            // 5) Clear references
            currentTask = null;
            currentThread = null;
            workerThreads = null;
        });
        // match the same shadow effect you used for Start
        
        // Add drop shadow to button
        DropShadow buttonShadow = new DropShadow();
        buttonShadow.setColor(Color.rgb(0, 0, 0, 0.3));
        buttonShadow.setRadius(10);
        buttonShadow.setOffsetY(3);
        scanButton.setEffect(buttonShadow);
        stopButton.setEffect(buttonShadow);
        
        progressBar = new ProgressBar(0);
        progressBar.setPrefWidth(300);
        progressBar.setVisible(false);
        progressBar.setStyle("-fx-accent: #4e54c8;");
        
        controlBox.getChildren().addAll(scanButton, stopButton, progressBar);
        
        vbox.getChildren().addAll(formTitle, grid, controlBox);
        return vbox;
    }

    /**
     * Creates the log area
     */
    private VBox createLogArea() {
        VBox vbox = new VBox(10);
        vbox.setPadding(new Insets(20));
        
        Label logLabel = new Label("Scan Log:");
        logLabel.setFont(Font.font("Segoe UI", FontWeight.BOLD, 16));
        logLabel.setTextFill(Color.WHITE);
        
        logArea = new TextArea();
        logArea.setEditable(false);
        logArea.setPrefHeight(400); // Increased height for log area
        logArea.setStyle("-fx-background-color: rgba(0, 0, 0, 0.7); " +
                         "-fx-text-fill: #00ff00; " + // Green terminal-like text
                         "-fx-font-family: 'Consolas', 'Monaco', monospace; " +
                         "-fx-font-size: 14px; " +
                         "-fx-background-radius: 5;");
        
        // Add some initial text
        logArea.setText("Security Scanner initialized. Ready to scan targets.\n");
        
        vbox.getChildren().addAll(logLabel, logArea);
        VBox.setVgrow(logArea, Priority.ALWAYS); // Let the log area grow
        
        return vbox;
    }

    /**
     * Creates the results table area
     */
    private VBox createResultsArea() {
        VBox vbox = new VBox(10);
        vbox.setPadding(new Insets(20));
        
        vbox.setStyle(
        		  "-fx-background-color: rgba(255,255,255,0.95); " +
        		  "-fx-background-radius: 10; " +
        		  "-fx-padding: 10; " +
        		  "-fx-effect: dropshadow(gaussian, rgba(0,0,0,0.3), 10, 0, 0, 0);"
        		);
        vbox.setBorder(new Border(new BorderStroke(
        		  Color.LIGHTGRAY, BorderStrokeStyle.SOLID,
        		  new CornerRadii(10), new BorderWidths(1)
        		)));
        
        Label resultsLabel = new Label("Scan Results:");
        resultsLabel.setFont(Font.font("Segoe UI", FontWeight.BOLD, 16));
        resultsLabel.setTextFill(Color.BLACK);
        
        // Create table
        resultsTable = new TableView<>();
        resultsTable.setPlaceholder(new Label("No results yet. Start a scan to see issues."));
        resultsTable.setStyle("-fx-background-color: rgba(255, 255, 255, 0.9); " +
                             "-fx-table-cell-border-color: transparent; " +
                             "-fx-background-radius: 5;");
        
        resultsTable.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);
        resultsTable.setStyle(
          "-fx-border-color: #ccc; " +
          "-fx-border-width: 1; " +
          "-fx-border-radius: 5; " +
          "-fx-background-radius: 5;"
        );
        
        // Define columns
        TableColumn<SecurityIssue, String> titleCol = new TableColumn<>("Issue");
        titleCol.setCellValueFactory(new PropertyValueFactory<>("title"));
        titleCol.setPrefWidth(200);
        
        TableColumn<SecurityIssue, String> severityCol = new TableColumn<>("Severity");
        severityCol.setCellValueFactory(new PropertyValueFactory<>("severity"));
        severityCol.setPrefWidth(100);
        // Custom cell factory for coloring severity
        severityCol.setCellFactory(column -> new TableCell<SecurityIssue, String>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                
                if (item == null || empty) {
                    setText(null);
                    setStyle("");
                } else {
                    setText(item);
                    switch (item) {
                        case "HIGH":
                            setTextFill(Color.WHITE);
                            setStyle("-fx-background-color: #cc0000; -fx-font-weight: bold; -fx-background-radius: 3; -fx-padding: 2 8;");
                            break;
                        case "MEDIUM":
                            setTextFill(Color.WHITE);
                            setStyle("-fx-background-color: #ff9900; -fx-font-weight: bold; -fx-background-radius: 3; -fx-padding: 2 8;");
                            break;
                        case "LOW":
                            setTextFill(Color.WHITE);
                            setStyle("-fx-background-color: #0099cc; -fx-font-weight: bold; -fx-background-radius: 3; -fx-padding: 2 8;");
                            break;
                        case "INFO":
                            setTextFill(Color.WHITE);
                            setStyle("-fx-background-color: #339933; -fx-font-weight: bold; -fx-background-radius: 3; -fx-padding: 2 8;");
                            break;
                        default:
                            setTextFill(Color.BLACK);
                            break;
                    }
                }
            }
        });
        
        TableColumn<SecurityIssue, String> descriptionCol = new TableColumn<>("Description");
        descriptionCol.setCellValueFactory(new PropertyValueFactory<>("description"));
        descriptionCol.setPrefWidth(300);
        
        TableColumn<SecurityIssue, String> recommendationCol = new TableColumn<>("Recommendation");
        recommendationCol.setCellValueFactory(new PropertyValueFactory<>("recommendation"));
        recommendationCol.setPrefWidth(300);
        
        resultsTable.getColumns().addAll(titleCol, severityCol, descriptionCol, recommendationCol);
        resultsTable.setItems(issuesList);
        
        // Add a prettier save button
        Button saveButton = new Button("Save Results");
        saveButton.setOnAction(e -> saveResultsToDatabase());
        saveButton.setStyle("-fx-background-color: linear-gradient(to bottom, #1e3c72, #2a5298); " +
                           "-fx-text-fill: white; " +
                           "-fx-font-size: 14px; " +
                           "-fx-font-weight: bold; " +
                           "-fx-padding: 8 15; " +
                           "-fx-background-radius: 5;");
        
        // Add hover effect
        saveButton.setOnMouseEntered(e -> 
            saveButton.setStyle("-fx-background-color: linear-gradient(to bottom, #2a5298, #3a62b8); " +
                               "-fx-text-fill: white; " +
                               "-fx-font-size: 14px; " +
                               "-fx-font-weight: bold; " +
                               "-fx-padding: 8 15; " +
                               "-fx-background-radius: 5;"));
        
        saveButton.setOnMouseExited(e -> 
            saveButton.setStyle("-fx-background-color: linear-gradient(to bottom, #1e3c72, #2a5298); " +
                               "-fx-text-fill: white; " +
                               "-fx-font-size: 14px; " +
                               "-fx-font-weight: bold; " +
                               "-fx-padding: 8 15; " +
                               "-fx-background-radius: 5;"));
        
        // Add a shadow
        DropShadow saveShadow = new DropShadow();
        saveShadow.setColor(Color.rgb(0, 0, 0, 0.3));
        saveShadow.setRadius(5);
        saveShadow.setOffsetY(2);
        saveButton.setEffect(saveShadow);
        
        vbox.getChildren().addAll(resultsLabel, resultsTable, saveButton);
        return vbox;
    }

    /**
     * Shows a dialog with scan history
     */
    /**
     * Shows a dialog letting the user pick a past scan session,
     * then loads its issues into the table and log.
     */
    private void showHistoryDialog() {
        // Fetch sessions
        List<DatabaseManager.ScanSession> sessions = databaseManager.getScanSessions();

        // If none, inform the user
        if (sessions.isEmpty()) {
            Alert noHistory = new Alert(Alert.AlertType.INFORMATION);
            noHistory.setTitle("Scan History");
            noHistory.setHeaderText(null);
            noHistory.setContentText("No scan history found.");
            noHistory.initOwner(scanButton.getScene().getWindow());
            noHistory.showAndWait();
            return;
        }

        // Let the user choose one session
        ChoiceDialog<DatabaseManager.ScanSession> dialog =
            new ChoiceDialog<>(sessions.get(0), sessions);
        dialog.initOwner(scanButton.getScene().getWindow());
        dialog.setTitle("Scan History");
        dialog.setHeaderText("Select a scan session to view its results");
        dialog.setContentText("Session:");

        // Show and wait for selection
        Optional<DatabaseManager.ScanSession> choice = dialog.showAndWait();
        choice.ifPresent(session -> {
            // Clear and reload issues
            issuesList.clear();
            issuesList.addAll(
                databaseManager.getIssuesBySessionId(session.getId())
            );

            // Update the log
            logArea.clear();
            logMessage(String.format(
                "Loaded %d issues from %s scan of %s on %s",
                issuesList.size(),
                session.getScanType(),
                session.getTarget(),
                session.getScanDate()
            ));
        });
    }


    /**
     * Export results to a file (placeholder)
     */
    private void exportResults() {
        if (issuesList.isEmpty()) {
            showAlert("No Results", "There are no results to export.", Alert.AlertType.INFORMATION);
            return;
        }

        FileChooser chooser = new FileChooser();
        chooser.setTitle("Save Scan Results as PDF");
        chooser.getExtensionFilters().add(
          new FileChooser.ExtensionFilter("PDF Files", "*.pdf"));
        chooser.setInitialFileName("scan_results.pdf");

        File file = chooser.showSaveDialog(null);
        if (file == null) return;

        try (PDDocument doc = new PDDocument()) {
            PDPage page = new PDPage(PDRectangle.LETTER);
            doc.addPage(page);

            PDPageContentStream cs = new PDPageContentStream(doc, page);
            float margin = 50;
            float y = page.getMediaBox().getHeight() - margin;

            // Header row
            cs.setFont(PDType1Font.HELVETICA_BOLD, 12);
            cs.beginText();
            cs.newLineAtOffset(margin, y);
            cs.showText("Issue");
            cs.newLineAtOffset(200, 0);
            cs.showText("Severity");
            cs.newLineAtOffset(100, 0);
            cs.showText("Date");
            cs.endText();

            // Data rows
            cs.setFont(PDType1Font.HELVETICA, 10);
            y -= 20;
            for (SecurityIssue issue : issuesList) {
                if (y < margin) {
                    cs.close();
                    page = new PDPage(PDRectangle.LETTER);
                    doc.addPage(page);
                    cs = new PDPageContentStream(doc, page);
                    y = page.getMediaBox().getHeight() - margin;
                }
                cs.beginText();
                cs.newLineAtOffset(margin, y);
                cs.showText(truncate(issue.getTitle(), 30));
                cs.newLineAtOffset(200, 0);
                cs.showText(issue.getSeverity());
                cs.newLineAtOffset(100, 0);
                cs.showText(issue.getDiscoveryDate().toLocalDate().toString());
                cs.endText();
                y -= 15;
            }

            cs.close();
            doc.save(file);

            showAlert("Export Successful",
                      "PDF saved to:\n" + file.getAbsolutePath(),
                      Alert.AlertType.INFORMATION);

        } catch (IOException ex) {
            showAlert("Export Failed",
                      "Could not write PDF:\n" + ex.getMessage(),
                      Alert.AlertType.ERROR);
        }
    }

    // helper to trim long titles
    private String truncate(String s, int max) {
        return (s.length() <= max) ? s : s.substring(0, max - 3) + "...";
    }

    /**
     * Show About dialog
     */
    private void showAboutDialog() {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle("About Security Scanner");
        alert.setHeaderText("Security Scanner v1.0");
        alert.setContentText("A security vulnerability scanner for web applications and network hosts.\n\n" +
                            "Features:\n" +
                            "• Port scanning\n" +
                            "• HTTP security header analysis\n" +
                            "• SSL/TLS certificate verification\n\n" +
                            "Created for CS9053 Java Final Project");
        
        // Style the dialog
        DialogPane dialogPane = alert.getDialogPane();
        dialogPane.setStyle("-fx-background-color: #2a3950;");
        dialogPane.lookup(".content.label").setStyle("-fx-text-fill: white;");
        dialogPane.lookup(".header-panel").setStyle("-fx-background-color: #1a2940;");
        dialogPane.lookup(".header-panel .label").setStyle("-fx-text-fill: white; -fx-font-size: 16px;");
        
        dialogPane.getButtonTypes().stream()
            .map(dialogPane::lookupButton)
            .forEach(button -> button.setStyle("-fx-background-color: #4e54c8; -fx-text-fill: white;"));
        
        alert.showAndWait();
    }

    /**
     * Utility method to show alerts
     */
    private void showAlert(String title, String content, Alert.AlertType type) {
        Alert alert = new Alert(type);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(content);
        
        // Style the alert
        DialogPane dialogPane = alert.getDialogPane();
        dialogPane.setStyle("-fx-background-color: #2a3950;");
        dialogPane.lookup(".content.label").setStyle("-fx-text-fill: white;");
        dialogPane.getButtonTypes().stream()
            .map(dialogPane::lookupButton)
            .forEach(button -> button.setStyle("-fx-background-color: #4e54c8; -fx-text-fill: white;"));
        
        alert.showAndWait();
    }

    /**
     * Performs the scan based on selected scan type
     */
    private void performScan() {
        // Clear previous results
        issuesList.clear();
        logArea.clear();
        
        // Get target
        currentTarget = targetField.getText().trim();
        if (currentTarget.isEmpty()) {
            logMessage("Error: Please enter a target URL or IP address");
            showAlert("Missing Target", "Please enter a target URL or IP address to scan.", Alert.AlertType.WARNING);
            return;
        }
        
        // Get scan type
        currentScanType = scanTypeComboBox.getValue();
        
        // Disable UI controls and show progress
        scanButton.setDisable(true);
        progressBar.setVisible(true);
        progressBar.setProgress(0);
        
        logMessage("Starting " + currentScanType + " on " + currentTarget + "...");
        
        switch (currentScanType) {
            case "Port Scan":
                performPortScan(currentTarget);
                break;
            case "HTTP Security Headers":
                performHeaderScan(currentTarget);
                break;
            case "SSL/TLS Certificate":
                performSSLScan(currentTarget);
                break;
            default:
                logMessage("Unknown scan type: " + currentScanType);
                scanButton.setDisable(false);
                progressBar.setVisible(false);
                break;
        }
    }

    /**
     * Performs a port scan
     */
    private void performPortScan(String host) {
        // Parse port range
        String[] portRange = portRangeField.getText().split("-");
        int startPort = 1;
        int endPort = 1000;
        
        try {
            startPort = Integer.parseInt(portRange[0]);
            if (portRange.length > 1) {
                endPort = Integer.parseInt(portRange[1]);
            }
        } catch (NumberFormatException e) {
            logMessage("Error: Invalid port range format. Using default 1-1000");
            startPort = 1;
            endPort = 1000;
        }
        
        // Create the PortScanner task
        PortScanner scanner = new PortScanner(host, startPort, endPort, DEFAULT_TIMEOUT, DEFAULT_THREAD_POOL_SIZE);
        currentTask = scanner;
        
        // Handle progress updates
        scanner.progressProperty().addListener((obs, oldVal, newVal) -> 
            Platform.runLater(() -> progressBar.setProgress(newVal.doubleValue())));
        
        // Handle status messages
        scanner.messageProperty().addListener((obs, oldVal, newVal) -> 
            Platform.runLater(() -> logMessage(newVal)));
        
        // Handle completion
        scanner.stateProperty().addListener((obs, oldVal, newVal) -> {
            if (newVal == Worker.State.SUCCEEDED) {
                Platform.runLater(() -> {
                    List<SecurityIssue> issues = scanner.getValue();
                    issuesList.addAll(issues);
                    logMessage("Scan completed. Found " + issues.size() + " issues.");
                    saveResultsToDatabase();    
                    scanButton.setDisable(false);
                    stopButton.setDisable(true);
                    progressBar.setVisible(false);
                });
            } else if (newVal == Worker.State.FAILED) {
                Platform.runLater(() -> {
                    logMessage("Scan failed: " + scanner.getException().getMessage());
                    scanButton.setDisable(false);
                    stopButton.setDisable(true);
                    progressBar.setVisible(false);
                });
            } else if (newVal == Worker.State.CANCELLED) {
                Platform.runLater(() -> {
                    logMessage("Scan cancelled by user.");
                    scanButton.setDisable(false);
                    stopButton.setDisable(true);
                    progressBar.setVisible(false);
                });
            }
        });
        
        // Start the scan
        Thread scanThread = new Thread(scanner);
        currentThread = scanThread;
        scanThread.setDaemon(true);
        scanThread.start();
        
        // Store reference to worker threads for cancellation
        workerThreads = scanner.getWorkerThreads();
        
        // Enable the stop button
        stopButton.setDisable(false);
    }
    
    /**
     * Logs a message to the log area
     */
    private void logMessage(String message) {
        logArea.appendText(message + "\n");
    }

    /**
     * Save results to the database
     */
    private void saveResultsToDatabase() {
        if (issuesList.isEmpty()) {
            logMessage("No results to save.");
            showAlert("No Results", "There are no results to save to the database.", Alert.AlertType.WARNING);
            return;
        }
        
        if (currentTarget == null || currentScanType == null) {
            logMessage("Error: Missing scan information. Cannot save to database.");
            return;
        }
        
        // Save to database
        int savedCount = databaseManager.saveIssues(currentTarget, currentScanType, issuesList);
        
        if (savedCount > 0) {
            logMessage("Successfully saved " + savedCount + " issues to database.");
            showAlert("Save Successful", "Saved " + savedCount + " security issues to the database.", Alert.AlertType.INFORMATION);
        } else {
            logMessage("Failed to save issues to database.");
            showAlert("Save Failed", "Failed to save issues to the database.", Alert.AlertType.ERROR);
        }
    }

    /**
     * Performs an HTTP security header scan
     */
    private void performHeaderScan(String url) {
        HeaderScanner scanner = new HeaderScanner(url, DEFAULT_TIMEOUT);
        currentTask = scanner;
        
        // Handle progress updates
        scanner.progressProperty().addListener((obs, oldVal, newVal) -> 
            Platform.runLater(() -> progressBar.setProgress(newVal.doubleValue())));
        
        // Handle status messages
        scanner.messageProperty().addListener((obs, oldVal, newVal) -> 
            Platform.runLater(() -> logMessage(newVal)));
        
        // Handle completion
        scanner.stateProperty().addListener((obs, oldVal, newVal) -> {
            if (newVal == Worker.State.SUCCEEDED) {
                Platform.runLater(() -> {
                    List<SecurityIssue> issues = scanner.getValue();
                    issuesList.addAll(issues);
                    logMessage("Scan completed. Found " + issues.size() + " issues.");
                    saveResultsToDatabase();    // ← auto-persist
                    scanButton.setDisable(false);
                    stopButton.setDisable(true);
                    progressBar.setVisible(false);
                });
            } else if (newVal == Worker.State.FAILED) {
                Platform.runLater(() -> {
                    logMessage("Scan failed: " + scanner.getException().getMessage());
                    scanButton.setDisable(false);
                    stopButton.setDisable(true);
                    progressBar.setVisible(false);
                });
            } else if (newVal == Worker.State.CANCELLED) {
                Platform.runLater(() -> {
                    logMessage("Scan cancelled by user.");
                    scanButton.setDisable(false);
                    stopButton.setDisable(true);
                    progressBar.setVisible(false);
                });
            }
        });
        
        // Start the scan
        Thread scanThread = new Thread(scanner);
        currentThread = scanThread;
        scanThread.setDaemon(true);
        scanThread.start();
        
        // Enable the stop button
        stopButton.setDisable(false);
    }

    /**
     * Performs an SSL/TLS certificate scan
     */
    private void performSSLScan(String url) {
        SSLScanner scanner = new SSLScanner(url, DEFAULT_TIMEOUT);
        currentTask = scanner;
        
        // Handle progress updates
        scanner.progressProperty().addListener((obs, oldVal, newVal) -> 
            Platform.runLater(() -> progressBar.setProgress(newVal.doubleValue())));
        
        // Handle status messages
        scanner.messageProperty().addListener((obs, oldVal, newVal) -> 
            Platform.runLater(() -> logMessage(newVal)));
        
        // Handle completion
        scanner.stateProperty().addListener((obs, oldVal, newVal) -> {
            if (newVal == Worker.State.SUCCEEDED) {
                Platform.runLater(() -> {
                    List<SecurityIssue> issues = scanner.getValue();
                    issuesList.addAll(issues);
                    logMessage("Scan completed. Found " + issues.size() + " issues.");
                    saveResultsToDatabase();    // ← auto-persist
                    scanButton.setDisable(false);
                    stopButton.setDisable(true);
                    progressBar.setVisible(false);
                });
            } else if (newVal == Worker.State.FAILED) {
                Platform.runLater(() -> {
                    logMessage("Scan failed: " + scanner.getException().getMessage());
                    scanButton.setDisable(false);
                    stopButton.setDisable(true);
                    progressBar.setVisible(false);
                });
            } else if (newVal == Worker.State.CANCELLED) {
                Platform.runLater(() -> {
                    logMessage("Scan cancelled by user.");
                    scanButton.setDisable(false);
                    stopButton.setDisable(true);
                    progressBar.setVisible(false);
                });
            }
        });
        
        // Start the scan
        Thread scanThread = new Thread(scanner);
        currentThread = scanThread;
        scanThread.setDaemon(true);
        scanThread.start();
        
        // Enable the stop button
        stopButton.setDisable(false);
    }
}