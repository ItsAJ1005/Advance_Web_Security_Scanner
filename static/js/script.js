function processResults(data) {
    console.log("Processing results:", data);
    
    // Clear all results sections first
    document.querySelectorAll('.vulnerability-results').forEach(section => {
        section.innerHTML = '';
    });

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
