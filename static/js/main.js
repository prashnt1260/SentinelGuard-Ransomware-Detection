const fileInput = document.getElementById('fileInput');
const analyzeButton = document.getElementById('analyzeButton');
const uploadPanel = document.getElementById('upload-panel');
const analysisLog = document.getElementById('analysis-log');
const loadingOverlay = document.getElementById('loading');
const featurePanel = document.getElementById('feature-panel');
const featureList = document.getElementById('feature-list');

// --- 1. Drag & Drop Handlers ---
uploadPanel.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadPanel.classList.add('drag-over');
});

uploadPanel.addEventListener('dragleave', () => {
    uploadPanel.classList.remove('drag-over');
});

uploadPanel.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadPanel.classList.remove('drag-over');
    const files = e.dataTransfer.files;
    if (files.length) {
        fileInput.files = files; // Assign dropped files to the hidden input
        fileSelected();
    }
});

// Attach event listener for click on the drop zone
document.querySelector('.drag-drop-zone').addEventListener('click', () => {
    fileInput.click();
});

// Event listener for file selection change (either by click or drop)
fileInput.addEventListener('change', fileSelected);

// --- 2. File Selection Logic ---
function fileSelected() {
    // Reset UI state
    analysisLog.innerHTML = '<p>> System Ready. Awaiting file upload.</p>';
    featurePanel.style.display = 'none';
    
    // Hide the initial result box if present
    document.querySelectorAll('.alert-box, .safe-box').forEach(box => box.remove());


    if (fileInput.files.length > 0) {
        const fileName = fileInput.files[0].name;
        // Update the drop zone text to show file is ready
        document.querySelector('.drop-text').textContent = `FILE READY: ${fileName}`;
        document.querySelector('.drop-icon').classList.remove('fa-download');
        document.querySelector('.drop-icon').classList.add('fa-file-code'); // Change icon
        analyzeButton.disabled = false;
        logMessage(`> File "${fileName}" loaded successfully. Ready for analysis.`, 'var(--log-green)');
    } else {
        document.querySelector('.drop-text').textContent = `DROP PE FILE HERE`;
        document.querySelector('.drop-icon').classList.remove('fa-file-code');
        document.querySelector('.drop-icon').classList.add('fa-download');
        analyzeButton.disabled = true;
    }
}

// --- 3. Analysis Simulation and Logging ---
function logMessage(message, color = 'var(--log-green)') {
    const p = document.createElement('p');
    p.textContent = message;
    p.style.color = color;
    analysisLog.appendChild(p);
    analysisLog.scrollTop = analysisLog.scrollHeight; // Auto-scroll to bottom
}

function simulateAnalysis(fileName) {
    // Clear previous logs
    analysisLog.innerHTML = `<p>> Starting deep analysis for: ${fileName}</p>`;
    
    // Steps to simulate a complex analysis process
    const steps = [
        { msg: "> Validating PE file integrity...", delay: 500 },
        { msg: "> Extracting Header Metadata... [OK]", delay: 800 },
        { msg: "> Scanning API Imports (Dynamic Analysis Simulation)...", delay: 1200 },
        { msg: "> Calculating Section Entropy & Obfuscation Score...", delay: 1000 },
        { msg: "> Running ML Model Prediction Engine...", delay: 1500 },
    ];

    let delay = 0;
    steps.forEach(step => {
        delay += step.delay;
        setTimeout(() => logMessage(step.msg), delay); // Note: Color is defaulted to green/white
    });

    return delay; // Return total delay for the final result timing
}

// --- 4. Result Display Logic (Now uses actual features from backend) ---
function displayResults(data) {
    // Ensure data keys match the app.py response: prediction and probability_ransomware
    const predictionText = data.prediction || "UNKNOWN";
    const probabilityValue = data.probability_ransomware || 0;
    
    const isRansomware = predictionText.toLowerCase().includes('ransomware');
    const probabilityText = `${(probabilityValue * 100).toFixed(1)}%`;
    const finalResultColor = isRansomware ? 'var(--accent-red)' : 'var(--log-green)';
    
    // Remove previous result boxes
    document.querySelectorAll('.alert-box, .safe-box').forEach(box => box.remove());

    // 1. Final Result Log
    logMessage(`> CLASSIFICATION COMPLETE: ${predictionText} (P: ${probabilityText})`, finalResultColor);

    // 2. Add prominent result box
    const alertBox = document.createElement('div');
    alertBox.className = isRansomware ? 'alert-box' : 'safe-box';
    
    const iconClass = isRansomware ? 'fa-skull-crossbones' : 'fa-check-circle';
    const message = isRansomware ? 
        `[ALERT] RANSOMWARE DETECTED!` : 
        `[CLEAN] NO THREAT FOUND!`;

    alertBox.innerHTML = `<i class="fas ${iconClass}"></i> ${message} <span>(P: ${probabilityText})</span>`;
    analysisLog.appendChild(alertBox);
    analysisLog.scrollTop = analysisLog.scrollHeight;

    // 3. Populate Feature Analysis Panel using data.top_features (THE FIX)
    featureList.innerHTML = '';
    
    // Use the features array sent by the Python backend
    const features = data.top_features || []; 
    
    if (features.length > 0) {
        logMessage(`> Displaying Top ${features.length} Most Important Features:`, 'var(--accent-blue)');
    } else {
        logMessage(`> No specific feature importances available from the model.`, 'var(--text-light)');
    }
    
    features.forEach(feature => {
        const li = document.createElement('li');
        // Display feature name and its importance score from Python
        // feature.name and feature.score are dynamic data from app.py
        li.textContent = `${feature.name} (Score: ${feature.score})`;
        
        // Use 'safe' class only if the feature type is explicitly 'safe'
        li.className = feature.type === 'safe' ? 'safe' : ''; 
        
        featureList.appendChild(li);
    });
    
    featurePanel.style.display = 'block';
}

// --- 5. Main Upload Function (The Core Fix: uses /predict) ---
function uploadFile() {
    const file = fileInput.files[0];
    if (!file) return;

    analyzeButton.disabled = true;
    loadingOverlay.style.display = 'flex';
    
    // Start the analysis log simulation (UI enhancement)
    const analysisDelay = simulateAnalysis(file.name); 

    const formData = new FormData();
    formData.append('file', file);
    
    // Wait for the simulated log to finish, then execute the real API call
    setTimeout(() => {
        // --- IMPORTANT: Using /predict as per your app.py ---
        fetch('/predict', { 
            method: 'POST',
            body: formData
        })
        .then(response => {
            if (!response.ok) {
                // Throw an error with the status for better debugging
                return response.text().then(text => { throw new Error(`HTTP Error ${response.status}: ${text}`); });
            }
            return response.json();
        })
        .then(data => {
            // Stop UI loading/simulation
            loadingOverlay.style.display = 'none';

            // Log the actual final result and display features
            displayResults(data); 

            analyzeButton.disabled = false;
        })
        .catch(error => {
            // Handle network errors or JSON parsing/HTTP errors
            loadingOverlay.style.display = 'none';
            logMessage(`> CRITICAL ERROR: Analysis failed. ${error.message}`, 'var(--accent-red)');
            console.error('Fetch Error:', error);
            analyzeButton.disabled = false;
        });

    }, analysisDelay + 500); // Wait a little extra time after the simulation finishes

}

// Initial state check
fileSelected();
