document.addEventListener('DOMContentLoaded', function() {
    const scanForm = document.getElementById('scanForm');
    const scanProgress = document.getElementById('scanProgress');
    const scanResults = document.getElementById('scanResults');
    const progressBar = document.querySelector('.progress-bar');
    const currentAttack = document.querySelector('.current-attack');
    const completedAttacks = document.getElementById('completedAttacks');
    const terminalContent = document.querySelector('.terminal-content');
    const owaspScanForm = document.getElementById('owaspScanForm');

    // Initialize form handlers
    if (scanForm) {
        // Handle Select All
        const selectAll = document.getElementById('selectAll');
        if (selectAll) {
            selectAll.addEventListener('change', function() {
                document.querySelectorAll('input[name="attacks"]').forEach(checkbox => {
                    checkbox.checked = this.checked;
                });
            });
        }

        // Handle form submission
        scanForm.addEventListener('submit', handleScanSubmit);
    }

    // Handle OWASP scan form submission
    if (owaspScanForm) {
        owaspScanForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const targetUrl = document.getElementById('owasp_target_url').value;
            
            // Show results card
            const scanResults = document.getElementById('scanResults');
            if (scanResults) {
                scanResults.style.display = 'block';
            }
            
            // Run OWASP scan
            runOWASPSan(targetUrl);
        });
    }

    // Add clear results button handler
    const clearResultsBtn = document.getElementById('clearResults');
    if (clearResultsBtn) {
        clearResultsBtn.addEventListener('click', function() {
            const scanProgress = document.getElementById('scanProgress');
            const scanResults = document.getElementById('scanResults');
            const completedAttacks = document.getElementById('completedAttacks');
            const resultsContent = document.getElementById('resultsContent');

            scanProgress.style.display = 'none';
            scanResults.style.display = 'none';
            completedAttacks.innerHTML = '';
            resultsContent.innerHTML = '';
        });
    }

    async function handleOwaspScanSubmit(e) {
        e.preventDefault();
        
        const targetUrl = document.getElementById('owasp_target_url').value;
        if (!targetUrl) {
            showToast('Please enter a target URL', 'warning');
            return;
        }

        // Reset and show progress
        resetScanProgress();
        scanProgress.style.display = 'block';
        scanResults.style.display = 'none';

        const formData = new FormData();
        formData.append('target_url', targetUrl);
        formData.append('scan_type', 'owasp');

        try {
            const response = await fetch('/owasp_scan', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                throw new Error('OWASP scan request failed');
            }

            const data = await response.json();
            if (data.scan_id) {
                pollScanStatus(data.scan_id);
            }
        } catch (error) {
            handleScanError(error);
        }
    }

    async function handleScanSubmit(e) {
        e.preventDefault();
        
        const selectedAttacks = Array.from(document.querySelectorAll('input[name="attacks"]:checked'))
            .map(cb => cb.value);
        
        if (selectedAttacks.length === 0) {
            showToast('Please select at least one attack type', 'warning');
            return;
        }

        // Reset and show progress
        resetScanProgress();
        scanProgress.style.display = 'block';
        scanResults.style.display = 'none';

        const formData = new FormData();
        formData.append('target_url', document.getElementById('target_url').value);
        selectedAttacks.forEach(attack => formData.append('attacks', attack));

        try {
            const response = await fetch('/scan', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                throw new Error('Scan request failed');
            }

            const data = await response.json();
            if (data.scan_id) {
                pollScanStatus(data.scan_id);
            }
        } catch (error) {
            handleScanError(error);
        }
    }

    function pollScanStatus(scanId) {
        const progressSection = document.getElementById('scanProgress');
        const progressBar = document.querySelector('.progress-bar');
        const currentAttackElem = document.querySelector('.current-attack');
        const completedAttacksElem = document.getElementById('completedAttacks');
        
        progressSection.style.display = 'block';
        
        const interval = setInterval(async () => {
            try {
                const response = await fetch(`/scan_status/${scanId}`);
                if (!response.ok) throw new Error('Network response was not ok');
                
                const data = await response.json();
                console.log('Scan status update:', data);
                
                // Update progress
                if (data.progress !== undefined) {
                    progressBar.style.width = `${data.progress}%`;
                    progressBar.textContent = `${data.progress}%`;
                }

                // Update current attack
                if (data.current_attack) {
                    currentAttackElem.textContent = `Running: ${data.current_attack}`;
                }

                // Update completed attacks
                if (data.completed_attacks && data.completed_attacks.length > 0) {
                    completedAttacksElem.innerHTML = data.completed_attacks
                        .map(attack => `<div class="alert alert-success mb-2">${attack} ✓</div>`)
                        .join('');
                }

                // Handle scan completion
                if (data.status === 'completed') {
                    clearInterval(interval);
                    if (data.results) {
                        displayResults(data.results);
                    }
                    currentAttackElem.textContent = 'Scan completed';
                } else if (data.status === 'failed') {
                    clearInterval(interval);
                    handleScanError(new Error(data.error || 'Scan failed'));
                }
            } catch (error) {
                clearInterval(interval);
                handleScanError(error);
            }
        }, 1000);
    }

    function resetScanProgress() {
        progressBar.style.width = '0%';
        progressBar.textContent = '0%';
        currentAttack.textContent = 'Initializing scan...';
        completedAttacks.innerHTML = '';
        terminalContent.innerHTML = '';
    }

    function updateProgress(progress, attackName) {
        progressBar.style.width = `${progress}%`;
        progressBar.textContent = `${progress}%`;
        
        if (attackName) {
            currentAttack.textContent = `Running: ${attackName}`;
            appendToTerminal(`Scanning: ${attackName}`);
        }
    }

    function updateCompletedAttacks(completedAttacks) {
        const completedList = document.getElementById('completedAttacks');
        if (completedList) {
            completedList.innerHTML = completedAttacks.map(attack => 
                `<div class="alert alert-success">${attack} ✓</div>`
            ).join('');
        }
    }

    function finishScan() {
        scanProgress.style.display = 'none';
        appendToTerminal('Scan finished', 'success');
    }

    function handleScanError(error) {
        scanProgress.style.display = 'none';
        showToast(`Scan error: ${error.message}`, 'error');
        appendToTerminal(`Error: ${error.message}`, 'error');
    }

    function showToast(message, type) {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        document.body.appendChild(toast);
        setTimeout(() => {
            toast.remove();
        }, 3000);
    }

    function runScan(url) {
        const loader = document.querySelector('.loader');
        const resultsContent = document.getElementById('resultsContent');
        
        // Clear previous results
        resultsContent.innerHTML = '';
        loader.style.display = 'block';
        
        // Disable scan button during scan
        document.getElementById('scanButton').disabled = true;
        
        fetch('/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `target_url=${encodeURIComponent(url)}&attacks=sql_injection,xss,ssrf`
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(scanResponse => {
            console.log('Scan Initiated:', scanResponse);
            
            // Poll for scan status
            function checkScanStatus() {
                fetch(`/scan_status/${scanResponse.scan_id}`)
                .then(response => response.json())
                .then(statusData => {
                    console.log('Scan Status:', statusData);
                    
                    if (statusData.status === 'completed') {
                        loader.style.display = 'none';
                        document.getElementById('scanButton').disabled = false;
                        
                        // Log raw results for debugging
                        console.log('Raw Scan Results:', JSON.stringify(statusData.results, null, 2));
                        
                        // Detailed logging of each scan type
                        Object.entries(statusData.results || {}).forEach(([scanType, findings]) => {
                            console.log(`${scanType.toUpperCase()} Findings:`, JSON.stringify(findings, null, 2));
                        });
                        
                        // Ensure results are displayed
                        if (statusData.results && Object.keys(statusData.results).length > 0) {
                            displayResults(statusData.results);
                        } else {
                            showToast('No vulnerabilities found', 'info');
                        }
                    } else if (statusData.status === 'failed') {
                        loader.style.display = 'none';
                        document.getElementById('scanButton').disabled = false;
                        showToast(`Scan failed: ${statusData.error}`, 'error');
                    } else {
                        // Continue polling if not completed
                        setTimeout(checkScanStatus, 1000);
                    }
                })
                .catch(error => {
                    console.error('Status Check Error:', error);
                    loader.style.display = 'none';
                    document.getElementById('scanButton').disabled = false;
                    showToast(`Scan status error: ${error.message}`, 'error');
                });
            }
            
            // Start polling
            checkScanStatus();
        })
        .catch(error => {
            console.error('Scan Initiation Error:', error);
            loader.style.display = 'none';
            document.getElementById('scanButton').disabled = false;
            showToast(`Scan failed: ${error.message}`, 'error');
        });
    }

    function displayResults(results) {
        console.log('Display Results Called with:', JSON.stringify(results, null, 2));
        
        const resultsSection = document.getElementById('scanResults');
        const resultsContent = document.getElementById('resultsContent');
        
        resultsSection.style.display = 'block';
        
        if (!results || Object.keys(results).length === 0) {
            resultsContent.innerHTML = '<div class="alert alert-info">No vulnerabilities found</div>';
            return;
        }

        let html = '<div class="vulnerabilities-list">';
        
        // Iterate through each scan type
        Object.entries(results).forEach(([scanType, findings]) => {
            console.log(`Processing ${scanType}:`, JSON.stringify(findings, null, 2));
            
            // Ensure findings is an array
            const vulnerabilityList = Array.isArray(findings) ? findings : 
                (findings.vulnerabilities || [findings]);
            
            if (vulnerabilityList.length > 0) {
                html += `
                    <div class="vulnerability-group mb-4">
                        <h4 class="alert alert-secondary">${formatScanType(scanType)}</h4>
                        <div class="list-group">
                `;
                
                vulnerabilityList.forEach(finding => {
                    // Ensure all expected fields exist
                    const safeFind = {
                        type: finding.type || finding.vulnerability || 'Vulnerability Found',
                        severity: finding.severity || 'Unknown',
                        url: finding.url || 'N/A',
                        method: finding.method || 'N/A',
                        parameter: finding.parameter || 'N/A',
                        payload: finding.payload || 'No payload details',
                        evidence: finding.evidence || 'No additional evidence',
                        details: finding.details || 'No specific details',
                        recommendation: finding.recommendation || 'Implement proper security measures'
                    };

                    const severityColor = getSeverityColor(safeFind.severity);
                    
                    html += `
                        <div class="list-group-item">
                            <div class="d-flex justify-content-between align-items-center">
                                <h5 class="mb-1">${safeFind.type}</h5>
                                <span class="badge bg-${severityColor}">${safeFind.severity}</span>
                            </div>
                            <div class="vulnerability-details">
                                <p class="mb-1"><strong>Vulnerable URL:</strong> ${safeFind.url}</p>
                                <p class="mb-1"><strong>HTTP Method:</strong> ${safeFind.method}</p>
                                <p class="mb-1"><strong>Vulnerable Parameter:</strong> ${safeFind.parameter}</p>
                                <div class="payload-section">
                                    <strong>Payload Used:</strong>
                                    <pre class="bg-light p-2 rounded"><code>${escapeHtml(safeFind.payload)}</code></pre>
                                </div>
                                <p class="mb-1"><strong>Evidence:</strong> ${safeFind.evidence}</p>
                                <p class="mb-1"><strong>Details:</strong> ${safeFind.details}</p>
                                <div class="mt-2 recommendation-section">
                                    <strong>Recommendation:</strong>
                                    <p class="mb-0">${safeFind.recommendation}</p>
                                </div>
                            </div>
                        </div>
                    `;
                });
                
                html += '</div></div>';
            }
        });
        
        html += '</div>';
        resultsContent.innerHTML = html;
    }

    function displayOWASPResults(results) {
        const resultsContent = document.getElementById('resultsContent');
        if (!resultsContent) return;

        // Clear previous results
        resultsContent.innerHTML = '';

        // Check if results are empty
        if (Object.keys(results).length === 0) {
            resultsContent.innerHTML = '<div class="alert alert-info">No vulnerabilities detected</div>';
            return;
        }

        // Create results HTML
        let resultsHTML = '<h3>OWASP Top 10 Vulnerabilities</h3>';

        // Iterate through vulnerability categories
        Object.entries(results).forEach(([category, vulnerabilities]) => {
            resultsHTML += `
                <div class="vulnerability-category">
                    <h4>${category}</h4>
                    ${vulnerabilities.map(vuln => `
                        <div class="vulnerability-item ${vuln.risk.toLowerCase()}">
                            <strong>Type:</strong> ${vuln.type || vuln.header || 'Unknown'}<br>
                            <strong>Risk:</strong> ${vuln.risk || 'Not specified'}<br>
                            ${vuln.url ? `<strong>URL:</strong> ${vuln.url}<br>` : ''}
                            ${vuln.description ? `<strong>Description:</strong> ${vuln.description}<br>` : ''}
                            ${vuln.recommendation ? `<strong>Recommendation:</strong> ${vuln.recommendation}` : ''}
                        </div>
                    `).join('')}
                </div>
            `;
        });

        resultsContent.innerHTML = resultsHTML;
    }

    function formatScanType(scanType) {
        // Convert snake_case or camelCase to Title Case
        return scanType
            .replace(/([A-Z])/g, ' $1')  // Add space before capital letters
            .replace(/_/g, ' ')          // Replace underscores with spaces
            .replace(/\w\S*/g, function(txt){
                return txt.charAt(0).toUpperCase() + txt.substr(1).toLowerCase();
            });
    }

    function getSeverityColor(severity) {
        severity = (severity || '').toLowerCase();
        switch(severity) {
            case 'high': return 'danger';
            case 'medium': return 'warning';
            case 'low': return 'info';
            default: return 'secondary';
        }
    }

    function escapeHtml(unsafe) {
        return unsafe
             .replace(/&/g, "&amp;")
             .replace(/</g, "&lt;")
             .replace(/>/g, "&gt;")
             .replace(/"/g, "&quot;")
             .replace(/'/g, "&#039;");
    }

    function appendToTerminal(message, type = '') {
        const line = document.createElement('div');
        line.className = `terminal-line ${type}`;
        line.textContent = message;
        terminalContent.appendChild(line);
        terminalContent.scrollTop = terminalContent.scrollHeight;
    }

    function runOWASPSan(url) {
        console.log('OWASP Scan started for URL:', url);

        // Debugging: Log all potential loader elements
        const loaderSelectors = [
            '.loader', 
            '#loader', 
            '.scan-loader', 
            '.loading-spinner'
        ];

        let loader = null;
        for (let selector of loaderSelectors) {
            loader = document.querySelector(selector);
            if (loader) {
                console.log('Loader found with selector:', selector);
                break;
            }
        }

        const resultsContent = document.getElementById('resultsContent');
        
        // Extensive logging for debugging
        console.log('Loader element:', loader);
        console.log('Results content element:', resultsContent);
        
        if (!loader) {
            console.error('No loader element found. Checked selectors:', loaderSelectors);
            alert('Loader element not found');
            return;
        }
        
        if (!resultsContent) {
            console.error('Results content element not found');
            alert('Results display area missing');
            return;
        }
        
        // Safe loader display
        try {
            if (loader.style) {
                loader.style.display = 'block';
            } else {
                loader.classList.add('loading');
            }
        } catch (e) {
            console.error('Error showing loader:', e);
        }
        
        // Clear previous results
        resultsContent.innerHTML = '';
        
        // Ensure URL has protocol
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'https://' + url;
        }
        
        fetch('/owasp_scan', {  // Ensure this matches your Flask route exactly
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `target_url=${encodeURIComponent(url)}`
        })
        .then(response => {
            console.log('Scan response received:', response);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(scanResponse => {
            console.log('Full scan response:', scanResponse);
            
            // Hide loader safely
            try {
                if (loader.style) {
                    loader.style.display = 'none';
                } else {
                    loader.classList.remove('loading');
                }
            } catch (e) {
                console.error('Error hiding loader:', e);
            }
            
            if (scanResponse.status === 'completed') {
                console.log('Scan completed, results:', scanResponse.results);
                displayOWASPResults(scanResponse.results);
            } else {
                console.warn('Scan not completed:', scanResponse);
                showToast('Scan failed', 'error');
                resultsContent.innerHTML = `<div class="alert alert-danger">Scan Failed: ${scanResponse.error || 'Unknown error'}</div>`;
            }
        })
        .catch(error => {
            console.error('FULL OWASP Scan Error:', error);
            
            // Hide loader safely
            try {
                if (loader.style) {
                    loader.style.display = 'none';
                } else {
                    loader.classList.remove('loading');
                }
            } catch (e) {
                console.error('Error hiding loader:', e);
            }
            
            showToast(`Scan failed: ${error.message}`, 'error');
            resultsContent.innerHTML = `<div class="alert alert-danger">Failed to start scan: ${error.message}</div>`;
        });
    }

    function displayVulnerabilities(vulnerabilities) {
        const container = document.getElementById('vulnerabilities-container');
        container.innerHTML = ''; // Clear previous results

        if (Object.keys(vulnerabilities).length === 0) {
            container.innerHTML = '<p class="text-success">No vulnerabilities detected!</p>';
            return;
        }

        // Use a Set to track unique vulnerabilities
        const uniqueVulnerabilities = new Set();

        Object.entries(vulnerabilities).forEach(([category, issues]) => {
            issues.forEach(issue => {
                // Create a unique key for each vulnerability
                const vulnerabilityKey = JSON.stringify({
                    type: issue.type,
                    description: issue.description,
                    recommendation: issue.recommendation
                });

                // Only add if not already present
                if (!uniqueVulnerabilities.has(vulnerabilityKey)) {
                    uniqueVulnerabilities.add(vulnerabilityKey);

                    const vulnerabilityCard = document.createElement('div');
                    vulnerabilityCard.className = `card vulnerability-card risk-${issue.risk.toLowerCase()}`;
                    
                    const riskColor = {
                        'Critical': 'danger',
                        'High': 'danger',
                        'Medium': 'warning',
                        'Low': 'info'
                    }[issue.risk] || 'secondary';

                    vulnerabilityCard.innerHTML = `
                        <div class="card-header bg-${riskColor} text-white">
                            <strong>${category}</strong>
                        </div>
                        <div class="card-body">
                            <h5 class="card-title">${issue.type}</h5>
                            <p class="card-text">
                                <strong>Risk:</strong> <span class="badge bg-${riskColor}">${issue.risk}</span><br>
                                <strong>Description:</strong> ${issue.description}<br>
                                <strong>Recommendation:</strong> ${issue.recommendation}
                            </p>
                            ${issue.url ? `<p><strong>Affected URL:</strong> ${issue.url}</p>` : ''}
                        </div>
                    `;

                    container.appendChild(vulnerabilityCard);
                }
            });
        });

        // If no unique vulnerabilities were found
        if (container.children.length === 0) {
            container.innerHTML = '<p class="text-success">No vulnerabilities detected!</p>';
        }
    }

    function performVulnerabilityScan() {
        const targetUrl = document.getElementById('urlInput').value;
        
        // Show loading spinner
        const vulnerabilitiesContainer = document.getElementById('vulnerabilities-container');
        vulnerabilitiesContainer.innerHTML = `
            <div class="text-center">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Scanning...</span>
                </div>
                <p>Performing comprehensive vulnerability scan...</p>
            </div>
        `;

        // Ensure the scan button exists before adding event listener
        const scanButton = document.getElementById('scanButton');
        if (scanButton) {
            scanButton.addEventListener('click', performVulnerabilityScan);
        }

        // Use the correct endpoint
        fetch('/owasp-scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: targetUrl })
        })
        .then(response => response.json())
        .then(data => {
            displayVulnerabilities(data.results || {});
        })
        .catch(error => {
            console.error('Error:', error);
            vulnerabilitiesContainer.innerHTML = `
                <div class="alert alert-danger">
                    Error performing vulnerability scan: ${error.message}
                </div>
            `;
        });
    }
});
