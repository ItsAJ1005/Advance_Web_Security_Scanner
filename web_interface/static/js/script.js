function appendToTerminal(message, type = '') {
    const terminal = document.getElementById('terminalOutput');
    const line = document.createElement('div');
    line.className = `terminal-line ${type}`;
    line.textContent = `$ ${message}`;
    terminal.appendChild(line);
    terminal.scrollTop = terminal.scrollHeight;
}

document.getElementById('scanForm').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const form = e.target;
    const resultsDiv = document.getElementById('results');
    const loader = document.querySelector('.loader');
    const resultsContent = document.getElementById('resultsContent');
    const terminalOutput = document.getElementById('terminalOutput');
    
    // Clear previous results
    resultsContent.innerHTML = '';
    loader.style.display = 'block';
    
    appendToTerminal('Starting new scan...');
    appendToTerminal(`Target URL: ${form.target_url.value}`);
    
    const formData = new FormData(form);
    const selectedAttacks = formData.getAll('attacks');
    appendToTerminal(`Selected attacks: ${selectedAttacks.join(', ')}`);
    
    fetch('/scan', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        loader.style.display = 'none';
        appendToTerminal('Scan completed', 'success');
        displayResults(data);
    })
    .catch(error => {
        loader.style.display = 'none';
        appendToTerminal(`Error: ${error.message}`, 'error');
        resultsContent.innerHTML = `<div class="error">Error: ${error.message}</div>`;
    });
});

function displayResults(data) {
    const resultsContent = document.getElementById('resultsContent');
    let html = '';
    let vulnerabilitiesFound = false;
    
    for (const [attackType, vulnerabilities] of Object.entries(data)) {
        if (vulnerabilities.length > 0) {
            vulnerabilitiesFound = true;
            appendToTerminal(`Found ${vulnerabilities.length} vulnerabilities in ${attackType}`, 'warning');
            
            html += `<h3>${formatAttackType(attackType)}</h3>`;
            vulnerabilities.forEach(vuln => {
                html += `
                    <div class="vulnerability-card ${vuln.severity.toLowerCase()}">
                        <h4>${vuln.vulnerability}</h4>
                        <p><strong>URL:</strong> ${vuln.url}</p>
                        <p><strong>Severity:</strong> ${vuln.severity}</p>
                        ${vuln.parameter ? `<p><strong>Parameter:</strong> ${vuln.parameter}</p>` : ''}
                        ${vuln.payload ? `<p><strong>Payload:</strong> ${vuln.payload}</p>` : ''}
                    </div>
                `;
            });
        } else {
            appendToTerminal(`No vulnerabilities found in ${attackType}`, 'success');
        }
    }
    
    resultsContent.innerHTML = html || '<p class="no-vulns">No vulnerabilities found.</p>';
    
    if (vulnerabilitiesFound) {
        appendToTerminal('⚠️ Vulnerabilities detected! Check the results below.', 'warning');
    } else {
        appendToTerminal('✅ No vulnerabilities detected!', 'success');
    }
}

function formatAttackType(type) {
    return type.split('_')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ');
}
