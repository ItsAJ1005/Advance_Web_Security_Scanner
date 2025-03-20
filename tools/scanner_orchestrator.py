import subprocess
import logging
import json
from typing import Dict, List
import os
from concurrent.futures import ThreadPoolExecutor

class ToolOrchestrator:
    def __init__(self):
        self.tools = {
            'sqlmap': {
                'command': 'sqlmap',
                'args': ['--batch', '--random-agent'],
                'check': ['sqlmap', '--version']
            },
            'nikto': {
                'command': 'nikto',
                'args': ['-Format', 'json'],
                'check': ['nikto', '-Version']
            },
            'nmap': {
                'command': 'nmap',
                'args': ['-sV', '-sC'],
                'check': ['nmap', '--version']
            },
            'wpscan': {
                'command': 'wpscan',
                'args': ['--format', 'json'],
                'check': ['wpscan', '--version']
            },
            'sslyze': {
                'command': 'sslyze',
                'args': ['--json_out'],
                'check': ['sslyze', '--version']
            }
        }
        self.verify_tools()

    def verify_tools(self):
        """Verify that required tools are installed"""
        missing_tools = []
        for tool, config in self.tools.items():
            try:
                subprocess.run(
                    config['check'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True
                )
                logging.info(f"{tool} found and working")
            except (subprocess.SubprocessError, FileNotFoundError):
                missing_tools.append(tool)
                logging.warning(f"{tool} not found or not working")
        
        if missing_tools:
            logging.error(f"Missing tools: {', '.join(missing_tools)}")
            raise RuntimeError(f"Required tools not found: {', '.join(missing_tools)}")

    def scan_target(self, target_url: str, selected_tools: List[str] = None) -> Dict:
        """Run selected tools against the target"""
        if not selected_tools:
            selected_tools = list(self.tools.keys())

        results = {}
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = []
            for tool in selected_tools:
                if tool in self.tools:
                    futures.append(
                        executor.submit(self.run_tool, tool, target_url)
                    )

            for future in futures:
                tool_result = future.result()
                if tool_result:
                    results.update(tool_result)

        return results

    def run_tool(self, tool_name: str, target_url: str) -> Dict:
        """Run a specific tool and return its results"""
        try:
            tool_config = self.tools[tool_name]
            command = [tool_config['command']] + tool_config['args'] + [target_url]
            
            logging.info(f"Running {tool_name} against {target_url}")
            
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300  # 5 minute timeout
            )

            return self.parse_tool_output(tool_name, result.stdout, result.stderr)

        except subprocess.TimeoutExpired:
            logging.error(f"{tool_name} scan timed out")
            return {tool_name: {'error': 'Scan timed out'}}
        except Exception as e:
            logging.error(f"Error running {tool_name}: {e}")
            return {tool_name: {'error': str(e)}}

    def parse_tool_output(self, tool_name: str, stdout: str, stderr: str) -> Dict:
        """Parse tool output into a standardized format"""
        try:
            if tool_name == 'sqlmap':
                return self.parse_sqlmap_output(stdout)
            elif tool_name == 'nikto':
                return self.parse_nikto_output(stdout)
            elif tool_name == 'nmap':
                return self.parse_nmap_output(stdout)
            elif tool_name == 'wpscan':
                return self.parse_wpscan_output(stdout)
            elif tool_name == 'sslyze':
                return self.parse_sslyze_output(stdout)
            
        except Exception as e:
            logging.error(f"Error parsing {tool_name} output: {e}")
            return {tool_name: {'error': f"Failed to parse output: {str(e)}"}}

    def parse_sqlmap_output(self, output: str) -> Dict:
        vulnerabilities = []
        if 'sqlmap identified' in output.lower():
            vulnerabilities.append({
                'type': 'SQL Injection',
                'evidence': output,
                'severity': 'High'
            })
        return {'sqlmap': vulnerabilities}

    # Add other parsing methods for different tools...
