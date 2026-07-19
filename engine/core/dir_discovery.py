"""
Directory Discovery Module
Finds hidden directories and files using common wordlists
"""
import requests
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

class DirectoryDiscoverer:
    # Common directories and files
    COMMON_PATHS = [
        # Admin panels
        '/admin', '/administrator', '/admin.php', '/admin/', '/wp-admin', '/phpmyadmin',
        '/cpanel', '/control', '/panel', '/dashboard', '/manage',
        
        # API endpoints
        '/api', '/api/v1', '/api/v2', '/rest', '/graphql', '/swagger', '/api-docs',
        
        # Common files
        '/robots.txt', '/sitemap.xml', '/.well-known/security.txt', '/humans.txt',
        
        # Config/sensitive files
        '/config', '/configuration', '/.env', '/.git', '/.svn', '/.htaccess',
        '/web.config', '/config.php', '/settings.php', '/database.yml',
        
        # Backups
        '/backup', '/backups', '/old', '/temp', '/tmp', '/.bak', '/db_backup.sql',
        
        # Upload directories
        '/uploads', '/upload', '/files', '/media', '/images', '/assets', '/static',
        '/public', '/resources', '/data',
        
        # Common pages
        '/login', '/signin', '/signup', '/register', '/logout', '/forgot-password',
        '/search', '/contact', '/about', '/help', '/support',
        
        # Development
        '/test', '/testing', '/dev', '/development', '/staging', '/debug',
        '/phpinfo.php', '/info.php', '/_profiler',
        
        # CMS specific
        '/wp-content', '/wp-includes', '/wp-json', '/xmlrpc.php',
        '/sites/default/files', '/modules', '/themes',
        
        # Other
        '/download', '/downloads', '/docs', '/documentation', '/readme',
        '/changelog', '/version', '/status', '/health'
    ]
    
    def __init__(self, target_url, timeout=3, session=None):
        """
        Args:
            target_url: Target URL to discover paths on
            timeout: Per-request timeout in seconds
            session: Optional pre-configured requests.Session (e.g. one carrying
                auth headers/cookies applied by an Authenticator). When omitted, a
                plain, unauthenticated session is created as before.
        """
        self.base_url = target_url.rstrip('/')
        self.timeout = timeout
        self.session = session if session is not None else requests.Session()
        if session is None:
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            })
    
    def check_path(self, path):
        """Check if a path exists"""
        test_url = urljoin(self.base_url, path)
        try:
            response = self.session.get(test_url, timeout=self.timeout, allow_redirects=False, verify=False)
            
            # Consider these status codes as "found"
            if response.status_code in [200, 201, 301, 302, 307, 308, 401, 403]:
                logger.info(f"Found: {test_url} [{response.status_code}]")
                return {
                    'path': path,
                    'url': test_url,
                    'status': response.status_code,
                    'size': len(response.content),
                    'type': self._get_type(path, response)
                }
            return None
        except Exception as e:
            logger.debug(f"Error checking {test_url}: {e}")
            return None
    
    def _get_type(self, path, response):
        """Determine type of discovered resource"""
        if path.endswith(('.php', '.asp', '.jsp', '.do')):
            return 'script'
        elif path.endswith(('.txt', '.xml', '.json', '.yml', '.yaml')):
            return 'config/data'
        elif '/admin' in path or '/panel' in path:
            return 'admin'
        elif '/api' in path or '/graphql' in path:
            return 'api'
        elif '/.git' in path or '/.svn' in path or '/.env' in path:
            return 'sensitive'
        elif response.status_code in [401, 403]:
            return 'protected'
        else:
            return 'directory'
    
    def discover(self, paths=None, max_workers=20, callback=None):
        """
        Discover directories in parallel
        Args:
            paths: List of paths to check (default: common paths)
            max_workers: Number of parallel workers
            callback: Callback for each found path
        Returns:
            List of discovered paths
        """
        if paths is None:
            paths = self.COMMON_PATHS

        # Size the connection pool to the actual concurrency level. requests'
        # default HTTPAdapter pool_maxsize (10) is far below max_workers (commonly
        # 30 here); with more concurrent workers than pool slots, requests logs
        # "Connection pool is full, discarding connection" and opens a fresh,
        # non-pooled connection per excess request instead of reusing one — wasteful
        # and, under load, a source of connection churn. Every path targets the
        # same host, so pool_maxsize (connections per host) is what matters here.
        adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=max(max_workers, 10))
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

        discovered = []

        logger.info(f"Starting directory discovery on {self.base_url}")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_path = {executor.submit(self.check_path, path): path for path in paths}
            
            for future in as_completed(future_to_path):
                result = future.result()
                if result:
                    discovered.append(result)
                    if callback:
                        callback(result)
        
        logger.info(f"Directory discovery complete. Found {len(discovered)} paths")
        return discovered
