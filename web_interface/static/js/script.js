document.addEventListener('DOMContentLoaded', function() {
    const scanForm = document.getElementById('scanForm');
    const selectAll = document.getElementById('selectAll');
    const progressBar = document.querySelector('.progress-bar');
    const progressDiv = document.querySelector('.progress');
    const terminalOutput = document.getElementById('terminalOutput');

    // Handle Select All checkbox
    if (selectAll) {
        selectAll.addEventListener('change', function() {
            document.querySelectorAll('input[name="attacks"]').forEach(checkbox => {
                checkbox.checked = this.checked;
            });
        });
    }

    // Handle form submission
    if (scanForm) {
        scanForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const selectedAttacks = Array.from(document.querySelectorAll('input[name="attacks"]:checked'))
                .map(cb => cb.value);
            
            if (selectedAttacks.length === 0) {
                showToast('Please select at least one attack type', 'warning');
                return;
            }

            const formData = new FormData();
            formData.append('target_url', document.getElementById('target_url').value);
            selectedAttacks.forEach(attack => formData.append('attacks', attack));

            // Show loading state
            document.querySelector('.loader').style.display = 'block';
            document.getElementById('resultsContent').innerHTML = '';

            try {
                const response = await fetch('/scan', {
                    method: 'POST',
                    body: formData
                });

                const data = await response.json();
                if (data.scan_id) {
                    pollScanStatus(data.scan_id);
                }
            } catch (error) {
                handleScanError(error);
            }
        });
    }

    function pollScanStatus(scanId) {
        const interval = setInterval(async () => {
            try {
                const response = await fetch(`/scan_status/${scanId}`);
                const data = await response.json();
                
                updateProgress(data.progress);
                
                if (data.status === 'completed') {
                    clearInterval(interval);
                    displayResults(data.results);
                    document.querySelector('.loader').style.display = 'none';
                } else if (data.status === 'failed') {
                    clearInterval(interval);
                    handleScanError(new Error(data.error));
                }
            } catch (error) {
                clearInterval(interval);
                handleScanError(error);
            }
        }, 1000);
    }

    function updateProgress(progress) {
        progressBar.style.width = `${progress}%`;
        progressBar.textContent = `${progress}%`;
    }

    function finishScan() {
        progressDiv.style.display = 'none';
        appendToTerminal('Scan finished', 'success');
    }

    function handleScanError(error) {
        progressDiv.style.display = 'none';
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
});

function appendToTerminal(message, type = '') {
    const terminal = document.getElementById('terminalOutput');
    const line = document.createElement('div');
    line.className = `terminal-line ${type}`;
    line.textContent = `$ ${message}`;
    terminal.appendChild(line);
    terminal.scrollTop = terminal.scrollHeight;
}

function displayResults(data) {
    const resultsContent = document.getElementById('resultsContent');
    let html = '<div class="scan-summary">';
    let totalVulnerabilities = 0;

    // Group vulnerabilities by severity
    const severityGroups = {
        'High': [],
        'Medium': [],
        'Low': []
    };

    for (const [scanType, results] of Object.entries(data)) {
        if (results && results.length > 0) {
            results.forEach(vuln => {
                if (vuln.severity) {
                    severityGroups[vuln.severity].push({
                        ...vuln,
                        scanType
                    });
                    totalVulnerabilities++;
                }
            });
        }
    }

    // Display summary
    html += `<h3>Scan Complete - Found ${totalVulnerabilities} vulnerabilities</h3>`;

    // Display vulnerabilities grouped by severity
    for (const [severity, vulns] of Object.entries(severityGroups)) {
        if (vulns.length > 0) {
            html += `
                <div class="severity-group ${severity.toLowerCase()}">
                    <h4>${severity} Severity (${vulns.length})</h4>
                    ${vulns.map(vuln => `
                        <div class="vulnerability-card">
                            <h5>${vuln.type || vuln.vulnerability}</h5>
                            <p><strong>Scanner:</strong> ${formatScanType(vuln.scanType)}</p>
                            <p><strong>URL:</strong> ${vuln.url || 'N/A'}</p>
                            ${vuln.parameter ? `<p><strong>Parameter:</strong> ${vuln.parameter}</p>` : ''}
                            ${vuln.evidence ? `<p><strong>Evidence:</strong> ${formatEvidence(vuln.evidence)}</p>` : ''}
                        </div>
                    `).join('')}
                </div>
            `;
        }
    }

    html += '</div>';
    resultsContent.innerHTML = html;

    // Hide loader and show completion message
    document.querySelector('.loader').style.display = 'none';
    appendToTerminal(`Scan completed - Found ${totalVulnerabilities} vulnerabilities`);
}

function formatAttackType(type) {
    return type.split('_')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ');
}
