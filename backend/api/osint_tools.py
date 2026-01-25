"""
MR-ROBOT OSINT Tools Module
Domain lookup, IP info, and username search across platforms.
"""
import re
import socket
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
import logging

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Platforms for username search
USERNAME_PLATFORMS = {
    'github': 'https://github.com/{}',
    'twitter': 'https://twitter.com/{}',
    'instagram': 'https://instagram.com/{}',
    'linkedin': 'https://linkedin.com/in/{}',
    'reddit': 'https://reddit.com/user/{}',
    'youtube': 'https://youtube.com/@{}',
    'tiktok': 'https://tiktok.com/@{}',
    'pinterest': 'https://pinterest.com/{}',
    'medium': 'https://medium.com/@{}',
    'dev.to': 'https://dev.to/{}',
    'hackernews': 'https://news.ycombinator.com/user?id={}',
    'keybase': 'https://keybase.io/{}',
    'gitlab': 'https://gitlab.com/{}',
    'bitbucket': 'https://bitbucket.org/{}',
    'npm': 'https://www.npmjs.com/~{}',
    'pypi': 'https://pypi.org/user/{}',
}


class OsintTools:
    """
    Open Source Intelligence gathering tools.
    """
    
    def __init__(self):
        self.session = None
    
    async def domain_lookup(self, domain: str) -> Dict[str, Any]:
        """
        Perform comprehensive domain lookup.
        
        Args:
            domain: Domain to look up (e.g., example.com)
            
        Returns:
            WHOIS data, DNS records, and basic info
        """
        domain = self._clean_domain(domain)
        
        if not self._validate_domain(domain):
            return {
                'success': False,
                'error': 'Invalid domain format'
            }
        
        result = {
            'success': True,
            'domain': domain,
            'timestamp': datetime.now().isoformat()
        }
        
        # WHOIS lookup
        if WHOIS_AVAILABLE:
            try:
                w = whois.whois(domain)
                result['whois'] = {
                    'registrar': w.registrar if hasattr(w, 'registrar') else None,
                    'creation_date': str(w.creation_date) if hasattr(w, 'creation_date') else None,
                    'expiration_date': str(w.expiration_date) if hasattr(w, 'expiration_date') else None,
                    'name_servers': w.name_servers if hasattr(w, 'name_servers') else [],
                    'country': w.country if hasattr(w, 'country') else None,
                    'org': w.org if hasattr(w, 'org') else None,
                }
            except Exception as e:
                result['whois'] = {'error': str(e)}
        else:
            result['whois'] = {'error': 'WHOIS module not available'}
        
        # DNS lookup
        result['dns'] = await self._dns_lookup(domain)
        
        # IP lookup
        try:
            ip = socket.gethostbyname(domain)
            result['ip'] = ip
            result['ip_info'] = await self.ip_lookup(ip)
        except socket.gaierror:
            result['ip'] = None
            result['ip_info'] = {'error': 'Could not resolve domain'}
        
        return result
    
    async def ip_lookup(self, ip: str) -> Dict[str, Any]:
        """
        Get information about an IP address.
        
        Args:
            ip: IP address to look up
            
        Returns:
            Geolocation and basic info
        """
        if not self._validate_ip(ip):
            return {'success': False, 'error': 'Invalid IP address'}
        
        result = {
            'success': True,
            'ip': ip,
            'timestamp': datetime.now().isoformat()
        }
        
        # Use free IP-API service
        if REQUESTS_AVAILABLE:
            try:
                response = requests.get(
                    f'http://ip-api.com/json/{ip}',
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') == 'success':
                        result['location'] = {
                            'country': data.get('country'),
                            'country_code': data.get('countryCode'),
                            'region': data.get('regionName'),
                            'city': data.get('city'),
                            'zip': data.get('zip'),
                            'lat': data.get('lat'),
                            'lon': data.get('lon'),
                            'timezone': data.get('timezone'),
                            'isp': data.get('isp'),
                            'org': data.get('org'),
                            'as': data.get('as'),
                        }
                    else:
                        result['location'] = {'error': data.get('message', 'Unknown error')}
            except Exception as e:
                result['location'] = {'error': str(e)}
        else:
            result['location'] = {'error': 'Requests module not available'}
        
        # Reverse DNS
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            result['reverse_dns'] = hostname
        except socket.herror:
            result['reverse_dns'] = None
        
        return result
    
    async def username_search(
        self,
        username: str,
        platforms: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Search for username across platforms.
        
        Args:
            username: Username to search
            platforms: List of platforms to check (defaults to all)
            
        Returns:
            Platform URLs and availability hints
        """
        username = username.strip().lower()
        
        if not re.match(r'^[a-zA-Z0-9_.-]{1,30}$', username):
            return {
                'success': False,
                'error': 'Invalid username format'
            }
        
        if platforms is None:
            platforms = list(USERNAME_PLATFORMS.keys())
        
        results = []
        
        for platform in platforms:
            if platform not in USERNAME_PLATFORMS:
                continue
            
            url = USERNAME_PLATFORMS[platform].format(username)
            
            # Check if profile exists (basic check)
            exists = None
            if REQUESTS_AVAILABLE:
                try:
                    response = requests.head(
                        url,
                        timeout=5,
                        allow_redirects=True,
                        headers={'User-Agent': 'Mozilla/5.0'}
                    )
                    exists = response.status_code == 200
                except:
                    exists = None
            
            results.append({
                'platform': platform,
                'url': url,
                'exists': exists,
                'status': 'found' if exists else ('not_found' if exists is False else 'unknown')
            })
        
        # Sort: found first, then unknown, then not_found
        results.sort(key=lambda x: {'found': 0, 'unknown': 1, 'not_found': 2}.get(x['status'], 3))
        
        return {
            'success': True,
            'username': username,
            'platforms_checked': len(results),
            'found': len([r for r in results if r['status'] == 'found']),
            'results': results,
            'timestamp': datetime.now().isoformat()
        }
    
    async def subdomain_enum(self, domain: str) -> Dict[str, Any]:
        """
        Basic subdomain enumeration using common prefixes.
        """
        domain = self._clean_domain(domain)
        
        common_subdomains = [
            'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'admin', 'api', 'dev', 'staging', 'test', 'beta', 'app',
            'cdn', 'static', 'assets', 'img', 'images', 'media',
            'blog', 'shop', 'store', 'secure', 'vpn', 'remote',
            'portal', 'dashboard', 'panel', 'cpanel', 'webdisk',
            'm', 'mobile', 'docs', 'help', 'support', 'status'
        ]
        
        found = []
        
        for sub in common_subdomains:
            subdomain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                found.append(subdomain)
            except socket.gaierror:
                pass
        
        return {
            'success': True,
            'domain': domain,
            'subdomains_checked': len(common_subdomains),
            'subdomains_found': len(found),
            'subdomains': found,
            'timestamp': datetime.now().isoformat()
        }
    
    async def _dns_lookup(self, domain: str) -> Dict[str, Any]:
        """Perform DNS lookups for various record types."""
        if not DNS_AVAILABLE:
            return {'error': 'DNS module not available'}
        
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10
        
        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
                records[rtype] = [str(rdata) for rdata in answers]
            except dns.resolver.NoAnswer:
                records[rtype] = []
            except dns.resolver.NXDOMAIN:
                records[rtype] = []
            except Exception as e:
                records[rtype] = []
        
        return records
    
    def _clean_domain(self, domain: str) -> str:
        """Clean domain input."""
        domain = domain.strip().lower()
        domain = re.sub(r'^https?://', '', domain)
        domain = domain.split('/')[0]
        return domain
    
    def _validate_domain(self, domain: str) -> bool:
        """Validate domain format."""
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'
        return bool(re.match(pattern, domain))
    
    def _validate_ip(self, ip: str) -> bool:
        """Validate IP address format."""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False


# Export singleton
osint_tools = OsintTools()
