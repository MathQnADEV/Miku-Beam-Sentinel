import sys
import os
import logging

# Add engine to Python path
engine_path = os.path.join(os.path.dirname(__file__), '../../..')
sys.path.insert(0, engine_path)

from engine.core.target import Target
from engine.scanners.registry import select_scanners
import requests

logger = logging.getLogger(__name__)


class ScanExecutor:
    """Executes vulnerability scans using the scanning engine"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Miku-Beam-Sentinel/1.0'
        })
        logger.info("ScanExecutor initialized")

    def _select_scanners(self, tech_stack):
        """
        Smart scanner selection based on discovered technologies.

        Delegates to the shared declarative registry (engine/scanners/registry.py)
        so every scanner (all 23) is reachable and "Unknown" tech defaults to
        "run it" rather than "skip it" — see that module for the rationale.
        """
        selected = select_scanners(tech_stack, self.session)
        logger.info(f"Smart selection: {len(selected)} scanners chosen based on tech stack")
        return selected
    
    def execute_scan(self, scan_obj):
        """
        Execute a scan and save results
        
        Args:
            scan_obj: Scan model instance
            
        Returns:
            bool: True if scan completed successfully, False if failed
        """
        from .models import Scan
        from scans.models import Vulnerability as VulnModel
        from django.utils import timezone
        from channels.layers import get_channel_layer
        from asgiref.sync import async_to_sync
        
        channel_layer = get_channel_layer()
        group_name = f'scan_{scan_obj.id}'
        
        def send_update(action, log, progress=None, data=None):
            payload = {
                'type': 'scan_update',
                'data': {
                    'action': action,
                    'log': f"[{timezone.now().strftime('%H:%M:%S')}] {log}",
                    'progress': progress,
                    ** (data or {})
                }
            }
            async_to_sync(channel_layer.group_send)(group_name, payload)

        logger.info(f"Starting scan execution for scan {scan_obj.id}")
        send_update('Initializing', f"Starting scan for {scan_obj.project.target_url}", 5)
        
        # Update status to RUNNING
        scan_obj.status = 'RUNNING'
        scan_obj.save()
        
        try:
            # Create target from project URL
            target = Target(url=scan_obj.project.target_url)
            logger.info(f"Scanning target: {target.url}")
            send_update('Resolving', f"Target resolved: {target.url}", 5)
            
            # =================================================================
            # PHASE 1: RECONNAISSANCE (5-30%)
            # =================================================================
            logger.info("=== Starting Reconnaissance Phase ===")
            send_update('Reconnaissance', "Starting reconnaissance phase...", 5, {'phase': 'reconnaissance'})
            
            # Import reconnaissance modules
            from engine.core.port_scanner import PortScanner
            from engine.core.tech_detector import TechDetector
            from engine.core.subdomain_enum import SubdomainEnumerator
            from engine.core.dir_discovery import DirectoryDiscoverer
            
            recon_data = {
                'open_ports': [],
                'technologies': {},
                'subdomains': [],
                'directories': [],
                'urls': []
            }
            
            # 1. Port Scanning (5-10%)
            logger.info("Starting port scan...")
            send_update('Port Scanning', "Scanning common ports...", 5)
            try:
                port_scanner = PortScanner(target.url, timeout=1)
                def on_port_found(port_info):
                    send_update('Port Scanning', f"Found open port: {port_info['port']} ({port_info['service']})", 7, {
                        'port_found': port_info
                    })
                recon_data['open_ports'] = port_scanner.scan(max_workers=20, callback=on_port_found)
                send_update('Port Scanning', f"Port scan complete. Found {len(recon_data['open_ports'])} open ports", 10)
            except Exception as e:
                logger.error(f"Port scan failed: {e}")
                send_update('Port Scanning', "Port scan failed, continuing...", 10)
            
            # 2. Technology Detection (10-15%)
            logger.info("Detecting technologies...")
            send_update('Tech Detection', "Analyzing technology stack...", 10)
            try:
                tech_detector = TechDetector(target.url, session=self.session)
                recon_data['technologies'] = tech_detector.detect()
                tech_summary = f"Server: {recon_data['technologies'].get('server', 'Unknown')}, Backend: {recon_data['technologies'].get('backend', 'Unknown')}"
                send_update('Tech Detection', f"Technologies detected: {tech_summary}", 15, {
                    'technologies': recon_data['technologies']
                })
            except Exception as e:
                logger.error(f"Tech detection failed: {e}")
                recon_data['technologies'] = {'server': 'Unknown', 'backend': 'Unknown', 'database': 'Unknown'}
                send_update('Tech Detection', "Tech detection failed, continuing...", 15)
            
            # 3. Subdomain Enumeration (15-20%)
            logger.info("Enumerating subdomains...")
            send_update('Subdomain Enum', "Enumerating subdomains...", 15)
            try:
                subdomain_enum = SubdomainEnumerator(target.url)
                def on_subdomain_found(subdomain):
                    send_update('Subdomain Enum', f"Found subdomain: {subdomain}", 17, {
                        'subdomain_found': subdomain
                    })
                recon_data['subdomains'] = subdomain_enum.enumerate(max_workers=30, callback=on_subdomain_found)
                send_update('Subdomain Enum', f"Found {len(recon_data['subdomains'])} subdomains", 20)
            except Exception as e:
                logger.error(f"Subdomain enumeration failed: {e}")
                send_update('Subdomain Enum', "Subdomain enumeration failed, continuing...", 20)
            
            # 4. Directory Discovery (20-25%)
            logger.info("Discovering directories...")
            send_update('Directory Discovery', "Scanning for directories and files...", 20)
            try:
                dir_discoverer = DirectoryDiscoverer(target.url, session=self.session)
                def on_dir_found(dir_info):
                    send_update('Directory Discovery', f"Found: {dir_info['path']} [{dir_info['status']}]", 22, {
                        'directory_found': dir_info
                    })
                recon_data['directories'] = dir_discoverer.discover(max_workers=30, callback=on_dir_found)
                send_update('Directory Discovery', f"Found {len(recon_data['directories'])} paths", 25)
            except Exception as e:
                logger.error(f"Directory discovery failed: {e}")
                send_update('Directory Discovery', "Directory discovery failed, continuing...", 25)
            
            # 5. Web Crawling (25-30%)
            logger.info("Starting web crawler...")
            send_update('Web Crawling', "Crawling site to discover URLs...", 25)
            try:
                from engine.core.crawler import Crawler
                def on_url_found(url):
                    recon_data['urls'].append(url)
                    send_update('Web Crawling', f"Found: {url}", 27, {'url_found': url})
                
                crawler = Crawler(target.url, max_depth=2, max_pages=30, callback=on_url_found, session=self.session)
                crawler.crawl()
                send_update('Web Crawling', f"Crawler finished. Found {len(recon_data['urls'])} URLs", 30)
            except Exception as e:
                logger.error(f"Crawler failed: {e}")
                recon_data['urls'] = [target.url]
                send_update('Web Crawling', "Crawler failed, using base URL", 30)
            
            logger.info(f"Reconnaissance complete. Ports: {len(recon_data['open_ports'])}, Subdomains: {len(recon_data['subdomains'])}, Directories: {len(recon_data['directories'])}, URLs: {len(recon_data['urls'])}")
            
            # =================================================================
            # PHASE 2: TARGETED VULNERABILITY SCANNING (30-85%)
            # =================================================================
            logger.info("=== Starting Targeted Vulnerability Scanning ===")
            send_update('Scanning', "Starting targeted vulnerability scanning...", 30, {'phase': 'scanning'})
            
            # Smart scanner selection based on discovered technologies
            selected_scanners = self._select_scanners(recon_data['technologies'])
            logger.info(f"Selected {len(selected_scanners)} scanners based on technology stack")
            
            all_vulnerabilities = []
            
            # Run selected scanners
            total_scanners = len(selected_scanners)
            for i, scanner in enumerate(selected_scanners):
                scanner_name = scanner.__class__.__name__
                current_progress = 30 + int((i / total_scanners) * 55)
                
                logger.info(f"Running {scanner_name}...")
                send_update('Scanning', f"Running {scanner_name}...", current_progress)
                
                # Define callback for payload updates
                def on_payload_tested(payload):
                    # Send payload update (throttled if needed, but for now direct)
                    # We send a specific 'payload' event type for the frontend to handle separately
                    payload_data = {
                        'type': 'scan_update',
                        'data': {
                            'scanner': scanner_name,
                            'payload': payload
                        }
                    }
                    async_to_sync(channel_layer.group_send)(group_name, payload_data)

                try:
                    # Execute scanner (individual requests have their own timeouts)
                    vulns = scanner.scan(target, callback=on_payload_tested)
                    all_vulnerabilities.extend(vulns)
                    logger.info(f"{scanner_name} found {len(vulns)} vulnerabilities")
                    
                    if vulns:
                        send_update('Vulnerability Found', f"{scanner_name} found {len(vulns)} vulnerabilities", current_progress, {
                            'vuln_count': len(all_vulnerabilities)
                        })
                        
                except Exception as scanner_error:
                    logger.error(f"Error in {scanner_name}: {scanner_error}")
                    send_update('Error', f"Error in {scanner_name}: {str(scanner_error)[:100]}", current_progress)
                    # Continue with other scanners even if one fails
            
            # =================================================================
            # PHASE 2.5: EXTERNAL ENGINE — NUCLEI (optional, if installed)
            # =================================================================
            try:
                from engine.integrations.nuclei_runner import run as run_nuclei, is_available as nuclei_available
                if nuclei_available():
                    send_update('Scanning', "Running Nuclei templates (external engine)...", 84, {'phase': 'scanning'})

                    def on_nuclei(msg):
                        async_to_sync(channel_layer.group_send)(group_name, {
                            'type': 'scan_update',
                            'data': {'scanner': 'nuclei', 'payload': msg}
                        })

                    nuclei_vulns = run_nuclei(target.url, timeout=240, callback=on_nuclei)
                    all_vulnerabilities.extend(nuclei_vulns)
                    send_update('Scanning', f"Nuclei finished: {len(nuclei_vulns)} findings", 85, {
                        'vuln_count': len(all_vulnerabilities)
                    })
                else:
                    logger.info("Nuclei not installed on PATH; skipping external engine")
                    send_update('Scanning', "Nuclei not installed — skipping optional external engine", 85)
            except Exception as e:
                logger.error(f"Nuclei stage failed: {e}")
                send_update('Scanning', "Nuclei stage failed, continuing...", 85)

            # =================================================================
            # PHASE 3: REPORTING (85-100%)
            # =================================================================
            logger.info("=== Starting Reporting Phase ===")
            send_update('Reporting', "Compiling results...", 85, {'phase': 'reporting'})
            
            # Save vulnerabilities to database
            logger.info(f"Saving {len(all_vulnerabilities)} vulnerabilities to database")
            send_update('Finalizing', "Saving results to database...", 90)
            
            for vuln in all_vulnerabilities:
                VulnModel.objects.create(
                    scan=scan_obj,
                    name=vuln.name,
                    description=vuln.description,
                    severity=vuln.severity,
                    evidence=vuln.evidence
                )

            # NOTE: Previous "demo mode" that fabricated fake SQLi/XSS findings when
            # no real vulnerabilities were found has been removed — a scanner must
            # never invent findings. An empty result set now means "nothing found".

            # (Removed: redundant second crawl + simulated subdomains/ports/tech that
            # were computed here but never saved. Real recon lives in recon_data above.)

            
            # Update scan to COMPLETED
            scan_obj.status = 'COMPLETED'
            scan_obj.completed_at = timezone.now()            
            # Store results with reconnaissance data
            results = {
                'total_vulnerabilities': len(all_vulnerabilities),
                'scanners_run': len(selected_scanners),
                'target_url': scan_obj.project.target_url,
                'reconnaissance': {
                    'open_ports': recon_data['open_ports'],
                    'tech_stack': recon_data['technologies'],
                    'subdomains': recon_data['subdomains'],
                    'subdirectories': [d.get('path', d) if isinstance(d, dict) else d for d in recon_data['directories']],
                    'discovered_urls': recon_data['urls'],
                    'attack_surface': {
                        'total_endpoints': len(recon_data['urls']) + len(recon_data['directories']),
                        'total_subdomains': len(recon_data['subdomains']),
                        'total_open_ports': len(recon_data['open_ports'])
                    }
                }
            }
            scan_obj.results = results
            scan_obj.save()
            
            logger.info(f"Scan {scan_obj.id} completed successfully with {len(all_vulnerabilities)} vulnerabilities")
            send_update('Completed', "Scan finished successfully.", 100)
            return True
            
        except Exception as e:
            # Mark scan as FAILED
            logger.error(f"Scan {scan_obj.id} failed: {e}", exc_info=True)
            scan_obj.status = 'FAILED'
            scan_obj.completed_at = timezone.now()
            scan_obj.results = {
                'error': str(e),
                'error_type': type(e).__name__
            }
            scan_obj.save()
            send_update('Failed', f"Scan failed: {str(e)}", 0)
            return False
