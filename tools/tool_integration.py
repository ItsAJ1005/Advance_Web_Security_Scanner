from tools.scanner_orchestrator import ToolOrchestrator
from typing import Dict, List
import logging

class IntegratedScanner:
    def __init__(self):
        self.orchestrator = ToolOrchestrator()
        self.scan_profiles = {
            'quick': ['nmap', 'nikto'],
            'full': ['nmap', 'nikto', 'sqlmap', 'wpscan', 'sslyze'],
            'web': ['nikto', 'sqlmap', 'wpscan'],
            'infrastructure': ['nmap', 'sslyze']
        }

    async def run_integrated_scan(self, target_url: str, profile: str = 'quick') -> Dict:
        """Run an integrated scan using multiple tools"""
        try:
            selected_tools = self.scan_profiles.get(profile, ['nmap', 'nikto'])
            results = self.orchestrator.scan_target(target_url, selected_tools)
            
            # Combine and standardize results
            standardized_results = self.standardize_results(results)
            
            return {
                'status': 'completed',
                'profile': profile,
                'tools_used': selected_tools,
                'findings': standardized_results
            }
            
        except Exception as e:
            logging.error(f"Integrated scan error: {e}")
            return {
                'status': 'failed',
                'error': str(e)
            }

    def standardize_results(self, results: Dict) -> List[Dict]:
        """Standardize results from different tools into a common format"""
        standardized = []
        
        for tool, findings in results.items():
            if isinstance(findings, list):
                for finding in findings:
                    standardized.append({
                        'source': tool,
                        'type': finding.get('type', 'Unknown'),
                        'severity': finding.get('severity', 'Medium'),
                        'evidence': finding.get('evidence', ''),
                        'details': finding
                    })
            elif isinstance(findings, dict):
                standardized.append({
                    'source': tool,
                    'type': 'Tool Output',
                    'severity': 'Info',
                    'evidence': str(findings),
                    'details': findings
                })

        return standardized
