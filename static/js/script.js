function runScan(url, attacks) {
    console.log("Starting scan with attacks:", attacks);  // Debug log
    document.getElementById('resultsContent').innerHTML = '';
    
    fetch('/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `target_url=${encodeURIComponent(url)}&attacks=${attacks.join(',')}`
    })
    .then(response => response.json())
    .then(data => {
        console.log("Received scan results:", data);  // Debug log
        if (data.scan_id) {
            pollScanStatus(data.scan_id);
        }
    })
    .catch(error => {
        console.error("Scan error:", error);
        document.getElementById('resultsContent').innerHTML = 
            `<div class="alert alert-danger">Error: ${error}</div>`;
    });
}

function processResults(data) {
    console.log("Processing results:", data);  // Debug log

    // Clear previous results
    document.querySelectorAll('.vulnerability-results').forEach(section => {
        section.innerHTML = '';
    });

    if (data.xxe_injection) {
        console.log("Found XXE results:", data.xxe_injection);  // Debug log
        displayXXEResults(data.xxe_injection);
    }

    if (data.ldap) {
        console.log("Processing LDAP results:", data.ldap);
        displayLDAPResults(data.ldap);
    }

    // Process each type of result
    if (data.brute_force) {
        console.log("Processing brute_force:", data.brute_force);
        displayBruteForceResults(data.brute_force);
    }
    
    if (data.idor) {
        console.log("Processing IDOR:", data.idor);
        displayIdorResults(data.idor);
    }
    
    if (data.port_scan) {
        console.log("Processing port_scan:", data.port_scan);
        // Make sure we're passing the correct data structure
        const portScanData = {
            target: data.port_scan.target,
            ip: data.port_scan.ip,
            total_open_ports: data.port_scan.total_open_ports,
            risk_summary: data.port_scan.risk_summary,
            findings: data.port_scan.findings
        };
        displayPortScanResults(portScanData);
    }

    if (data.ldap_injection) {
        console.log("Processing LDAP injection:", data.ldap_injection);
        displayLDAPResults(data.ldap_injection);
    }

    if (data.xxe_injection) {
        console.log("Processing XXE injection:", data.xxe_injection);
        displayXXEResults(data.xxe_injection);
    }
}

// Add error handling to displayPortScanResults
function displayPortScanResults(data) {
    console.log("Displaying port scan results:", data);
    
    const portSection = document.querySelector('#port-scan .vulnerability-results');
    const summarySection = document.querySelector('#port-scan .vulnerability-summary');
    
    if (!portSection || !summarySection) {
        console.error("Could not find port scan results sections");
        return;
    }
    
    // Clear previous results
    portSection.innerHTML = '';
    summarySection.innerHTML = '';
    
    if (!data || !data.findings || data.findings.length === 0) {
        summarySection.innerHTML = '<div class="alert alert-info">No open ports detected.</div>';
        return;
    }

    // Add summary section
    summarySection.innerHTML = `
        <div class="alert alert-danger">
            <h4 class="alert-heading">Port Scan Findings</h4>
            <p><strong>Target:</strong> ${data.target} (${data.ip})</p>
            <p><strong>Total Vulnerable Ports:</strong> ${data.total_open_ports}</p>
            <div class="risk-distribution mt-2">
                ${data.risk_summary.high > 0 ? 
                    `<p class="text-danger"><strong>HIGH RISK:</strong> ${data.risk_summary.high} critical services exposed</p>` : ''}
                ${data.risk_summary.medium > 0 ? 
                    `<p class="text-warning"><strong>MEDIUM RISK:</strong> ${data.risk_summary.medium} services vulnerable</p>` : ''}
                ${data.risk_summary.low > 0 ? 
                    `<p class="text-success"><strong>LOW RISK:</strong> ${data.risk_summary.low} minor issues</p>` : ''}
            </div>
        </div>
    `;

    // Group findings by severity
    const findingsBySeverity = {
        'High': [],
        'Medium': [],
        'Low': []
    };

    data.findings.forEach(finding => {
        findingsBySeverity[finding.severity].push(finding);
    });

    // Display findings by severity
    Object.entries(findingsBySeverity).forEach(([severity, findings]) => {
        if (findings.length > 0) {
            const severityClass = severity.toLowerCase();
            findings.forEach(finding => {
                const findingCard = `
                    <div class="vulnerability-card mb-3">
                        <div class="card-header d-flex justify-content-between">
                            <h4>Port Scan Vulnerability</h4>
                            <span class="severity-badge ${severityClass}">${severity}</span>
                        </div>
                        <div class="card-content">
                            <div class="port-info mb-3">
                                <p><strong>Service:</strong> ${finding.service}</p>
                                <p><strong>Port:</strong> ${finding.port}</p>
                                <p><strong>Description:</strong> ${finding.description}</p>
                            </div>
                            
                            <div class="vulnerability-details mb-3">
                                <p><strong>Details:</strong> ${finding.details}</p>
                                <div class="evidence-section">
                                    <p><strong>Evidence:</strong></p>
                                    <pre>${finding.evidence}</pre>
                                </div>
                            </div>

                            <div class="recommendations">
                                <h5>Security Recommendations:</h5>
                                <ul>
                                    ${finding.recommendation.split('\n')
                                        .map(rec => `<li>${rec.replace(/^\d+\.\s*/, '')}</li>`)
                                        .join('')}
                                </ul>
                            </div>
                        </div>
                    </div>
                `;
                portSection.innerHTML += findingCard;
            });
        }
    });
}

function displayLDAPResults(data) {
    console.log("Displaying LDAP injection results:", data);
    
    const ldapSection = document.querySelector('#ldap-injection .vulnerability-results');
    const summarySection = document.querySelector('#ldap-injection .vulnerability-summary');
    const template = document.getElementById('ldap-injection-template');
    
    if (!ldapSection || !summarySection || !template) {
        console.error("Could not find LDAP injection results sections");
        return;
    }
    
    // Clear previous results
    ldapSection.innerHTML = '';
    
    if (!data || data.length === 0) {
        summarySection.innerHTML = '<div class="alert alert-success">No LDAP injection vulnerabilities detected.</div>';
        return;
    }

    // Create summary
    summarySection.innerHTML = `
        <div class="alert alert-danger">
            <h4 class="alert-heading">LDAP Injection Vulnerabilities Detected!</h4>
            <p><strong>Found ${data.length} potential LDAP injection points</strong></p>
            <hr>
            <p class="mb-0">
                <i class="bi bi-exclamation-triangle-fill"></i>
                <strong>Critical Warning:</strong> LDAP injection vulnerabilities can lead to unauthorized access 
                and information disclosure.
            </p>
        </div>
    `;

    // Display each vulnerability
    data.forEach(vuln => {
        const clone = template.content.cloneNode(true);
        
        // Set severity badge
        const badge = clone.querySelector('.severity-badge');
        badge.textContent = vuln.severity;
        badge.classList.add(vuln.severity.toLowerCase());
        
        // Fill in vulnerability details
        clone.querySelector('.url').textContent = vuln.url || 'N/A';
        clone.querySelector('.method').textContent = vuln.method || 'N/A';
        clone.querySelector('.parameter').textContent = vuln.parameter || 'N/A';
        clone.querySelector('.payload').textContent = vuln.payload || 'No payload details';
        clone.querySelector('.evidence').textContent = vuln.evidence || 'No evidence provided';
        clone.querySelector('.details').textContent = vuln.details || 'No additional details';
        
        // Format recommendations as a list
        const recommendations = vuln.recommendation.split('\n')
            .filter(rec => rec.trim())
            .map(rec => rec.replace(/^\d+\.\s*/, ''))
            .join('\n• ');
        clone.querySelector('.recommendation').textContent = '• ' + recommendations;
        
        ldapSection.appendChild(clone);
    });
}

function displayXXEResults(data) {
    console.log("Displaying XXE injection results:", data);

    const xxeSection = document.querySelector('#xxe-injection .vulnerability-results');
    const summarySection = document.querySelector('#xxe-injection .vulnerability-summary');
    const template = document.getElementById('xxe-injection-template');

    if (!xxeSection || !summarySection || !template) {
        console.error("Could not find XXE injection results sections");
        return;
    }

    // Clear previous results
    xxeSection.innerHTML = '';

    if (!data || data.length === 0) {
        summarySection.innerHTML = '<div class="alert alert-success">No XXE injection vulnerabilities detected.</div>';
        return;
    }

    // Create summary
    summarySection.innerHTML = `
        <div class="alert alert-danger">
            <h4 class="alert-heading">XXE Injection Vulnerabilities Detected!</h4>
            <p><strong>Found ${data.length} potential XXE injection points</strong></p>
            <hr>
            <p class="mb-0">
                <i class="bi bi-exclamation-triangle-fill"></i>
                <strong>Critical Warning:</strong> XXE injection vulnerabilities can lead to unauthorized access 
                and information disclosure.
            </p>
        </div>
    `;

    // Display each vulnerability
    data.forEach(vuln => {
        const clone = template.content.cloneNode(true);

        // Set severity badge
        const badge = clone.querySelector('.severity-badge');
        badge.textContent = vuln.severity;
        badge.classList.add(vuln.severity.toLowerCase());

        // Fill in vulnerability details
        clone.querySelector('.url').textContent = vuln.url || 'N/A';
        clone.querySelector('.method').textContent = vuln.method || 'N/A';
        clone.querySelector('.payload').textContent = vuln.payload || 'No payload details';
        clone.querySelector('.evidence').textContent = vuln.evidence || 'No evidence provided';
        clone.querySelector('.details').textContent = vuln.details || 'No additional details';

        // Format recommendations as a list
        const recommendations = vuln.recommendation.split('\n')
            .filter(rec => rec.trim())
            .map(rec => rec.replace(/^\d+\.\s*/, ''))
            .join('\n• ');
        clone.querySelector('.recommendation').textContent = '• ' + recommendations;

        xxeSection.appendChild(clone);
    });
}
