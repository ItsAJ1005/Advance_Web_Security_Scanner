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

    function displayOWASPResults(results, url) {
        console.group('OWASP Results Display');
        console.log('Received results:', results);
        console.log('Target URL:', url);  // Log the URL

        // Find or create results container with multiple selectors
        const resultsContent = document.getElementById('resultsContent') || 
                                document.querySelector('.results-container') || 
                                (() => {
                                    const newElement = document.createElement('div');
                                    newElement.id = 'resultsContent';
                                    newElement.classList.add('results-container');
                                    document.body.appendChild(newElement);
                                    return newElement;
                                })();

        // Validate results
        if (!results || typeof results !== 'object') {
            console.warn('Invalid results format');
            resultsContent.innerHTML = '<div class="alert alert-warning">Invalid scan results</div>';
            console.groupEnd();
            return;
        }

        // Check if any vulnerabilities exist
        const hasVulnerabilities = Object.values(results).some(
            category => Array.isArray(category) && category.length > 0
        );

        if (!hasVulnerabilities) {
            resultsContent.innerHTML = `
                <div class="alert alert-info">
                    <strong>No vulnerabilities detected</strong>
                    <p>The scan was completed for ${url}, but no specific vulnerabilities were found.</p>
                </div>
            `;
            console.log('No vulnerabilities found');
            console.groupEnd();
            return;
        }

        // Build results HTML
        let resultsHTML = `<h3>OWASP Top 10 Vulnerabilities for ${url}</h3>`;

        Object.entries(results).forEach(([category, vulnerabilities]) => {
            if (Array.isArray(vulnerabilities) && vulnerabilities.length > 0) {
                resultsHTML += `
                    <div class="vulnerability-category">
                        <h4>${category}</h4>
                        ${vulnerabilities.map(vuln => `
                            <div class="vulnerability-item ${(vuln.risk || '').toLowerCase()}">
                                <strong>Type:</strong> ${vuln.type || vuln.header || 'Unknown'}<br>
                                <strong>Risk:</strong> ${vuln.risk || 'Not specified'}<br>
                                ${vuln.url ? `<strong>URL:</strong> ${vuln.url}<br>` : ''}
                                ${vuln.description ? `<strong>Description:</strong> ${vuln.description}<br>` : ''}
                                ${vuln.recommendation ? `<strong>Recommendation:</strong> ${vuln.recommendation}` : ''}
                            </div>
                        `).join('')}
                    </div>
                `;
            }
        });

        // Set results with error handling
        try {
            resultsContent.innerHTML = resultsHTML;
            console.log('Results displayed successfully');
        } catch (error) {
            console.error('Error displaying results:', error);
            resultsContent.textContent = 'Error displaying scan results';
        }

        console.groupEnd();
    }

    function displayVulnerabilities(vulnerabilities) {
        const container = document.getElementById('vulnerabilities-container');
        container.innerHTML = ''; // Clear previous results

        console.log('Full Vulnerabilities Object:', vulnerabilities);

        if (Object.keys(vulnerabilities).length === 0) {
            container.innerHTML = '<p class="text-success">No vulnerabilities detected!</p>';
            return;
        }

        // Special handling for port scan results
        if (vulnerabilities.port_scan && vulnerabilities.port_scan.length > 0) {
            const portScanDetails = vulnerabilities.port_scan.map(port => `
                <div class="vulnerability-item">
                    <strong>Port:</strong> ${port.port} 
                    <strong>Status:</strong> ${port.status} 
                    <strong>Service:</strong> ${port.service}
                </div>
            `).join('');

            vulnerabilities.port_scan = [{
                title: 'NETWORK - Open Ports Discovered',
                description: `Found ${vulnerabilities.port_scan.length} open ports on the target:`,
                details: portScanDetails
            }];
        }

        // Special handling for brute force results
        if (vulnerabilities.brute_force && vulnerabilities.brute_force.length > 0) {
            const bruteForceDetails = vulnerabilities.brute_force.map(attempt => `
                <div class="vulnerability-item brute-force-item">
                    <div class="row">
                        <div class="col-md-6">
                            <strong>Username:</strong> ${attempt.username}
                        </div>
                        <div class="col-md-6">
                            <strong>Password:</strong> ${attempt.password}
                        </div>
                    </div>
                    <div class="row mt-2">
                        <div class="col-md-6">
                            <strong>URL:</strong> ${attempt.url}
                        </div>
                        <div class="col-md-6">
                            <strong>Status Code:</strong> ${attempt.status_code}
                        </div>
                    </div>
                    <div class="row mt-2">
                        <div class="col-md-12">
                            <strong>Type:</strong> ${attempt.type}
                        </div>
                        <div class="col-md-12">
                            <strong>Severity:</strong> ${attempt.severity}
                        </div>
                        <div class="col-md-12">
                            <strong>Payload:</strong> ${attempt.payload}
                        </div>
                        <div class="col-md-12">
                            <strong>Evidence:</strong> ${attempt.evidence}
                        </div>
                        <div class="col-md-12">
                            <strong>Recommendation:</strong> ${attempt.recommendation}
                        </div>
                    </div>
                </div>
            `).join('');

            vulnerabilities.brute_force = [{
                title: 'AUTHENTICATION - Successful Brute Force Attempts',
                description: `Found ${vulnerabilities.brute_force.length} successful login attempts:`,
                details: bruteForceDetails,
                severity: 'Critical'
            }];
        }

        // Special handling for specific vulnerability types
        const specialHandling = {
            'brute_force': {
                title: 'AUTHENTICATION - Brute Force Vulnerability',
                severityClass: 'bg-danger',
                description: 'Multiple login attempts possible without proper authentication controls.',
                recommendations: [
                    'Implement strict account lockout mechanisms',
                    'Enforce strong password policies',
                    'Add multi-factor authentication',
                    'Implement CAPTCHA or advanced rate limiting',
                    'Monitor and log all authentication attempts'
                ]
            },
            'ldap_injection': {
                title: 'INJECTION - LDAP Injection Vulnerability',
                severityClass: 'bg-danger',
                description: 'Potential vulnerability allowing manipulation of LDAP queries.',
                recommendations: [
                    'Implement strict input validation',
                    'Use parameterized queries',
                    'Sanitize all user inputs',
                    'Apply least privilege principle',
                    'Use prepared statements'
                ]
            },
            'session_hijacking': {
                title: 'AUTHENTICATION - Session Hijacking Vulnerability',
                severityClass: 'bg-danger',
                description: 'Potential unauthorized access through session manipulation.',
                recommendations: [
                    'Use secure, httpOnly cookies',
                    'Implement proper session management',
                    'Regenerate session IDs after login',
                    'Use HTTPS for all sessions',
                    'Implement IP and device binding'
                ]
            },
            'xxe_injection': {
                title: 'INJECTION - XML External Entity (XXE) Vulnerability',
                severityClass: 'bg-danger',
                description: 'Potential XML parsing vulnerability allowing external entity exploitation.',
                recommendations: [
                    'Disable XML external entity processing',
                    'Use safe XML parsers',
                    'Validate and sanitize XML inputs',
                    'Use XML schema validation',
                    'Limit XML document size'
                ]
            },
            'sql_injection': {
                title: 'INJECTION - SQL Injection Vulnerability',
                severityClass: 'bg-danger',
                description: 'Potential vulnerability allowing manipulation of database queries.',
                recommendations: [
                    'Use parameterized queries',
                    'Implement input validation',
                    'Apply least privilege principle',
                    'Use ORM with built-in protections',
                    'Sanitize all user inputs'
                ]
            },
            'ssrf': {
                title: 'NETWORK - Server-Side Request Forgery (SSRF)',
                severityClass: 'bg-danger',
                description: 'Potential vulnerability allowing server-side request manipulation.',
                recommendations: [
                    'Validate and sanitize URL inputs',
                    'Use allow-lists for permitted URLs',
                    'Implement network-level restrictions',
                    'Disable unnecessary URL fetching functionality',
                    'Use DNS rebinding protection'
                ]
            },
            'xss': {
                title: 'WEB - Cross-Site Scripting (XSS)',
                severityClass: 'bg-warning',
                description: 'Potential vulnerability allowing script injection.',
                recommendations: [
                    'Implement output encoding',
                    'Use Content Security Policy (CSP)',
                    'Validate and sanitize user inputs',
                    'Use HttpOnly and Secure flags for cookies',
                    'Implement input validation'
                ]
            },
            'port_scan': {
                title: 'NETWORK - Open Ports Discovered',
                severityClass: 'bg-warning',
                description: 'Multiple open ports detected, potentially exposing network services.',
                recommendations: [
                    'Close unnecessary ports',
                    'Use firewall to restrict access',
                    'Implement network segmentation',
                    'Disable unused services',
                    'Regularly audit open ports'
                ]
            }
        };

        // Ensure all expected categories are processed
        const categoriesToProcess = [
            'brute_force', 
            'ldap_injection', 
            'session_hijacking', 
            'xxe_injection', 
            'sql_injection', 
            'ssrf', 
            'xss',
            'port_scan'
        ];

        categoriesToProcess.forEach(category => {
            console.log(`Processing ${category}:`, vulnerabilities[category] || []);
            
            // Skip if no vulnerabilities for this category
            if (!vulnerabilities[category] || vulnerabilities[category].length === 0) {
                return;
            }

            // Use special handling for known categories, fallback to generic for others
            const categoryConfig = specialHandling[category] || {
                title: `${category.toUpperCase()} Vulnerability`,
                severityClass: 'bg-warning',
                description: 'Potential security vulnerability detected.',
                recommendations: ['Conduct thorough security review']
            };

            // Vulnerability Card
            const vulnerabilityCard = document.createElement('div');
            vulnerabilityCard.classList.add('card', 'mb-3', 'vulnerability-card');
            
            const cardHeader = document.createElement('div');
            cardHeader.classList.add('card-header', categoryConfig.severityClass, 'text-white');
            cardHeader.textContent = categoryConfig.title;
            
            const cardBody = document.createElement('div');
            cardBody.classList.add('card-body');
            cardBody.innerHTML = `
                <p><strong>Severity:</strong> <span class="badge ${categoryConfig.severityClass}">High</span></p>
                <p><strong>Description:</strong> ${categoryConfig.description}</p>
                <p><strong>Recommendation:</strong> 
                    <ul>
                        ${categoryConfig.recommendations.map(rec => `<li>${rec}</li>`).join('')}
                    </ul>
                </p>
            `;
            
            vulnerabilityCard.appendChild(cardHeader);
            vulnerabilityCard.appendChild(cardBody);
            container.appendChild(vulnerabilityCard);

            // Detailed Vulnerability Table
            const vulnerabilityTable = document.createElement('div');
            vulnerabilityTable.classList.add('card', 'mb-3');
            
            const tableHeader = document.createElement('div');
            tableHeader.classList.add('card-header', 'bg-warning', 'text-dark');
            tableHeader.textContent = `${category.toUpperCase()} Vulnerability Details (${vulnerabilities[category].length} found)`;
            
            const tableBody = document.createElement('div');
            tableBody.classList.add('card-body', 'p-0');
            
            const table = document.createElement('table');
            table.classList.add('table', 'table-striped', 'table-bordered', 'mb-0');
            
            // Dynamic table headers based on available data
            const headers = new Set();
            vulnerabilities[category].forEach(issue => Object.keys(issue).forEach(key => headers.add(key)));
            
            table.innerHTML = `
                <thead>
                    <tr>
                        ${Array.from(headers).map(header => `<th>${header.replace(/_/g, ' ').toUpperCase()}</th>`).join('')}
                    </tr>
                </thead>
                <tbody>
                    ${vulnerabilities[category].map(issue => `
                        <tr class="table-danger">
                            ${Array.from(headers).map(header => `
                                <td>${issue[header] !== undefined ? issue[header] : 'N/A'}</td>
                            `).join('')}
                        </tr>
                    `).join('')}
                </tbody>
            `;
            
            tableBody.appendChild(table);
            vulnerabilityTable.appendChild(tableHeader);
            vulnerabilityTable.appendChild(tableBody);
            container.appendChild(vulnerabilityTable);
        });

        // If no vulnerabilities were found
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
        console.group('OWASP Scan Initialization');
        console.log('Scan started for URL:', url);

        // Advanced element creation and selection utility
        function findOrCreateElement(selectors, type = 'div', fallbackClass = '', fallbackId = '') {
            console.log('Searching for elements with selectors:', selectors);

            // Try existing selectors first
            for (let selector of selectors) {
                const element = document.querySelector(selector);
                if (element) {
                    console.log('Found existing element:', element);
                    return element;
                }
            }

            // Create fallback element if no existing element found
            const newElement = document.createElement(type);
            
            if (fallbackClass) {
                newElement.classList.add(fallbackClass);
            }
            
            if (fallbackId) {
                newElement.id = fallbackId;
            }

            // Ensure element is visible and in the document
            newElement.style.display = 'block';
            document.body.appendChild(newElement);

            console.warn('Created fallback element:', newElement);
            return newElement;
        }

        // Find or create loader and results elements with more robust selection
        const loaderSelectors = [
            '.loader', 
            '#loader', 
            '.scan-loader', 
            '.loading-spinner',
            'div[id*="loader"]'
        ];

        const resultsSelectors = [
            '#resultsContent', 
            '.results-container',
            'div[id*="results"]'
        ];

        let loader = null;
        let resultsContent = null;

        // Multiple attempts to find elements
        const elementAttempts = [
            () => document.querySelector('.loader'),
            () => document.getElementById('loader'),
            () => document.querySelector('#resultsContent'),
            () => document.querySelector('.results-container')
        ];

        for (let attempt of elementAttempts) {
            const element = attempt();
            if (element) {
                if (element.classList.contains('loader') || element.id.includes('loader')) {
                    loader = element;
                } else if (element.id.includes('results') || element.classList.contains('results-container')) {
                    resultsContent = element;
                }
            }
        }

        // Fallback creation if elements are missing
        if (!loader) {
            loader = document.createElement('div');
            loader.classList.add('loader');
            loader.id = 'scan-loader';
            loader.style.display = 'none';
            document.body.appendChild(loader);
        }

        if (!resultsContent) {
            resultsContent = document.createElement('div');
            resultsContent.id = 'resultsContent';
            resultsContent.classList.add('results-container');
            document.body.appendChild(resultsContent);
        }

        // Comprehensive error logging function
        function logError(message, error = null) {
            console.error(message, error);
            
            // Ensure resultsContent exists and is in the document
            if (!resultsContent.parentNode) {
                document.body.appendChild(resultsContent);
            }

            // Update results content with error message
            resultsContent.innerHTML = `
                <div class="alert alert-danger">
                    <strong>${message}</strong>
                    ${error ? `<p>${error.toString()}</p>` : ''}
                </div>
            `;
        }

        // Ensure loader and results content are ready
        try {
            // Ensure elements are visible and in the document
            if (loader) {
                loader.style.display = 'block';
                loader.textContent = 'Scanning...';
                if (!loader.parentNode) {
                    document.body.appendChild(loader);
                }
            }

            if (resultsContent) {
                resultsContent.innerHTML = '';
                if (!resultsContent.parentNode) {
                    document.body.appendChild(resultsContent);
                }
            }
        } catch (initError) {
            logError('Initialization error', initError);
            console.groupEnd();
            return;
        }

        // Ensure URL has protocol
        url = url.startsWith('http://') || url.startsWith('https://') 
            ? url 
            : 'https://' + url;

        // Perform scan with comprehensive error handling
        fetch('/owasp-scan', {
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
            
            // Hide loader
            if (loader) {
                loader.style.display = 'none';
            }

            // Process scan results
            if (scanResponse.status === 'completed') {
                console.log('Scan completed successfully');
                displayOWASPResults(scanResponse.results || {}, url);
            } else {
                logError('Scan not completed', scanResponse.error);
            }
        })
        .catch(error => {
            logError('Scan failed', error);
            
            // Ensure loader is hidden
            if (loader) {
                loader.style.display = 'none';
            }
        })
        .finally(() => {
            console.groupEnd();
        });
    }
});
