import re
import logging
import hashlib
from typing import List, Dict, Optional
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup


class URLUtils:
    @staticmethod
    def normalize_url(url: str) -> str:
        """Ensure URL has proper schema and formatting"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url.rstrip('/')
    
    @staticmethod
    def is_valid_url(url: str) -> bool:
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except ValueError:
            return False

    @staticmethod
    def join_url(base: str, path: str) -> str:
        """Safely join base URL with path"""
        base = URLUtils.normalize_url(base)
        return urljoin(base, path.lstrip('/'))

class RequestUtils:
    @staticmethod
    def extract_forms(html_content: str) -> List[Dict]:
        forms = []
        try:
            soup = BeautifulSoup(html_content, 'lxml')
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').lower(),
                    'inputs': []
                }
                
                for input_field in form.find_all(['input', 'textarea']):
                    if input_field.get('name'):  
                        form_data['inputs'].append({
                            'name': input_field.get('name', ''),
                            'type': input_field.get('type', 'text'),
                            'value': input_field.get('value', '')
                        })
                
                if form_data['inputs']:  
                    forms.append(form_data)
                    
            return forms
        except Exception as e:
            logging.error(f"Error extracting forms: {e}")
            return []