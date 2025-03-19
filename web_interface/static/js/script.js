document.addEventListener('DOMContentLoaded', function() {
    const scanForm = document.getElementById('scanForm');
    const scanProgress = document.getElementById('scanProgress');
    const scanResults = document.getElementById('scanResults');
    const progressBar = document.querySelector('.progress-bar');
    const currentAttack = document.querySelector('.current-attack');
    const completedAttacks = document.getElementById('completedAttacks');
    const terminalContent = document.querySelector('.terminal-content');

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
                console.log('Scan status update:', data); // Debug logging
                
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

    function displayResults(results) {
        const resultsSection = document.getElementById('scanResults');
        const resultsContent = document.getElementById('resultsContent');
        
        resultsSection.style.display = 'block';
        
        if (!results || Object.keys(results).length === 0) {
            resultsContent.innerHTML = '<div class="alert alert-info">No vulnerabilities found</div>';
            return;
        }

        let html = '<div class="vulnerabilities-list">';
        
        for (const [scanType, findings] of Object.entries(results)) {
            if (findings && findings.length > 0) {
                html += `
                    <div class="vulnerability-group mb-4">
                        <h4 class="alert alert-secondary">${formatScanType(scanType)}</h4>
                        <div class="list-group">
                `;
                
                findings.forEach(vuln => {
                    html += `
                        <div class="list-group-item">
                            <div class="d-flex justify-content-between align-items-center">
                                <h5 class="mb-1">${vuln.type || vuln.vulnerability || 'Vulnerability Found'}</h5>
                                <span class="badge bg-${getSeverityColor(vuln.severity)}">${vuln.severity || 'Unknown'}</span>
                            </div>
                            <p class="mb-1"><strong>URL:</strong> ${vuln.url || 'N/A'}</p>
                            ${vuln.parameter ? `<p class="mb-1"><strong>Parameter:</strong> ${vuln.parameter}</p>` : ''}
                            ${vuln.payload ? `<p class="mb-1"><strong>Payload:</strong> ${vuln.payload}</p>` : ''}
                            ${vuln.evidence ? `<p class="mb-1"><strong>Evidence:</strong> ${vuln.evidence}</p>` : ''}
                            ${vuln.issues ? `<p class="mb-1"><strong>Issues:</strong> ${Array.isArray(vuln.issues) ? vuln.issues.join(', ') : vuln.issues}</p>` : ''}
                        </div>
                    `;
                });
                
                html += '</div></div>';
            }
        }
        
        html += '</div>';
        resultsContent.innerHTML = html;
        resultsSection.scrollIntoView({ behavior: 'smooth' });
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

function getSeverityColor(severity) {
    switch (severity?.toLowerCase()) {
        case 'high': return 'danger';
        case 'medium': return 'warning';
        case 'low': return 'info';
        default: return 'secondary';
    }
}

function formatScanType(type) {
    return type.split('_')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ');
}
