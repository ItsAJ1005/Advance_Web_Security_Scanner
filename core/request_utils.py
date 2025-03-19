import requests
from typing import Dict, Optional
from urllib.parse import urljoin
import logging

class RequestUtils:
    @staticmethod
    def make_request(url: str, method: str = 'GET', **kwargs) -> Optional[requests.Response]:
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            if 'headers' in kwargs:
                headers.update(kwargs['headers'])
            kwargs['headers'] = headers
            
            response = requests.request(method, url, **kwargs)
            return response
            
        except Exception as e:
            logging.error(f"Request error: {e}")
            return None

    @staticmethod
    def extract_params(response: requests.Response) -> Dict:
        """Extract parameters from forms and URLs"""
        params = {}
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract from forms
            for form in soup.find_all('form'):
                for input_tag in form.find_all('input'):
                    name = input_tag.get('name')
                    if name:
                        params[name] = input_tag.get('value', '')
                        
            # Extract from URLs in links
            from urllib.parse import urlparse, parse_qs
            for a in soup.find_all('a', href=True):
                url = a['href']
                if '?' in url:
                    query = urlparse(url).query
                    params.update(parse_qs(query))
                    
        except Exception as e:
            logging.error(f"Error extracting parameters: {e}")
            
        return params
