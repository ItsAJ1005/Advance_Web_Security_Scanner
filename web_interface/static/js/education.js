const attacks = {
    sql_injection: {
        name: "SQL Injection",
        description: "SQL injection is a code injection technique used to attack data-driven applications.",
        how_it_works: "Attackers insert malicious SQL queries into input fields to manipulate the database.",
        mitigations: [
            "Use prepared statements",
            "Input validation",
            "Parameterized queries",
            "Least privilege principle"
        ],
        params: [
            {name: "payload", type: "select", options: ["' OR '1'='1", "admin'--", "' UNION SELECT * FROM users--"]}
        ]
    },
    xss: {
        name: "Cross-Site Scripting (XSS)",
        description: "XSS attacks inject malicious scripts into web pages viewed by other users.",
        how_it_works: "Attackers insert JavaScript code that executes in victims' browsers.",
        mitigations: [
            "Input sanitization",
            "Content Security Policy (CSP)",
            "Output encoding",
            "HttpOnly cookies"
        ],
        params: [
            {name: "payload", type: "select", options: ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]}
        ]
    }
    // ... more attacks ...
};

function launchAttack(attackId) {
    const attack = attacks[attackId];
    const modal = document.getElementById('attackModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalDescription = document.getElementById('modalDescription');
    const attackParams = document.getElementById('attackParams');
    
    modalTitle.textContent = attack.name;
    modalDescription.innerHTML = `
        <div class="attack-info">
            <p>${attack.description}</p>
            <h4>How it works:</h4>
            <p>${attack.how_it_works}</p>
            <h4>Mitigations:</h4>
            <ul>
                ${attack.mitigations.map(m => `<li>${m}</li>`).join('')}
            </ul>
        </div>
    `;
    
    // Generate parameter inputs
    attackParams.innerHTML = attack.params.map(param => `
        <div class="param-group">
            <label>${param.name}:</label>
            ${generateParamInput(param)}
        </div>
    `).join('');
    
    modal.style.display = 'block';
}

// ... rest of JavaScript functions ...
