import websockets
import asyncio
from core.base_scanner import BaseScanner

class WebSocketScanner(BaseScanner):
    def __init__(self, target_url: str):
        super().__init__(target_url)
        self.test_messages = [
            '{"type": "authenticate", "token": "test"}',
            '<script>alert("XSS")</script>',
            '\u0000test\u0000'  # Null byte injection
        ]

    async def _test_websocket(self, uri):
        vulnerabilities = []
        try:
            async with websockets.connect(uri) as websocket:
                for message in self.test_messages:
                    await websocket.send(message)
                    response = await websocket.recv()
                    
                    # Check for vulnerability indicators
                    if self._detect_vulnerability(response, message):
                        vulnerabilities.append({
                            'type': 'WebSocket Vulnerability',
                            'payload': message,
                            'response': response,
                            'risk': 'Medium'
                        })
        except Exception as e:
            self.logger.error(f"WebSocket test failed: {e}")
        
        return vulnerabilities

    def _detect_vulnerability(self, response, payload):
        """Detect potential WebSocket vulnerabilities"""
        vulnerability_indicators = [
            'error', 'exception', 
            'script>', '<svg', 
            'alert(', 'document.cookie'
        ]
        
        return any(
            indicator in response 
            for indicator in vulnerability_indicators
        )

    def scan(self):
        # Convert HTTP/HTTPS to WS/WSS
        ws_url = self.target_url.replace('http://', 'ws://').replace('https://', 'wss://')
        
        # Run async websocket scan
        vulnerabilities = asyncio.get_event_loop().run_until_complete(
            self._test_websocket(ws_url)
        )
        
        self.save_results(vulnerabilities)
        return vulnerabilities