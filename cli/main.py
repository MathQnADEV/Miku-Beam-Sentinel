import argparse
import json
import logging
import sys
from colorama import init, Fore, Style
from engine.core.target import Target
from engine.core.profiler import Profiler
from engine.core.auth import Authenticator, AuthType
from engine.scanners.registry import REGISTRY
from engine.reporting.reporter import Reporter

# Initialize colorama
init()

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("mikubeam.cli")

def print_banner():
    banner = fr"""{Fore.RED}
   (                                 
   )\ )             (                
  (()/(   (   (     )\ )  (       )  
   /(_))  )\  )(   (()/(  )(   ( /(  
  (_))   ((_)(()\   /(_))(()\  )(_)) 
  {Fore.WHITE}|ced|{Fore.RED}  | __| | _ ) ((_) (_))   ((_)((_) 
  | (__  | _ \ | '_| / -_) | '_| | U | 
   \___| |___/ |_|   \___| |_|   |___| 
                                       
  {Fore.BLUE}Miku Beam Sentinel v1.0{Style.RESET_ALL}
  {Fore.WHITE}Professional API Security Scanner{Style.RESET_ALL}
  {Fore.CYAN}Author: MathQnADEV (based on Cerberus API Sentinel by Sudeepa Wanigarathna){Style.RESET_ALL}
    """
    print(banner)

def build_parser():
    """Build the CLI argument parser.

    The --scan-<key> flags are generated from the shared scanner registry
    (engine/scanners/registry.py) instead of being hand-listed here, so a
    scanner only needs to be added in one place to become reachable from both
    the CLI and the web scan flow.
    """
    parser = argparse.ArgumentParser(description="Miku Beam Sentinel - API Security Scanner")
    parser.add_argument("-u", "--url", help="Target API URL (e.g., https://example.com/api)")
    parser.add_argument("-m", "--method", default="GET", help="HTTP Method (GET, POST, etc.)")
    parser.add_argument("--gui", action="store_true", help="Launch the Web GUI Dashboard")
    parser.add_argument("--headers", help="Custom headers (JSON format)")

    # Auth Arguments
    parser.add_argument("--auth-type", choices=["basic", "bearer", "api_key"], help="Authentication Type")
    parser.add_argument("--auth-token", help="Bearer Token")
    parser.add_argument("--auth-user", help="Basic Auth Username")
    parser.add_argument("--auth-pass", help="Basic Auth Password")

    # Scan Options
    parser.add_argument("--scan-all", action="store_true", help="Enable all scans")
    for spec in REGISTRY:
        parser.add_argument(f"--scan-{spec.key}", action="store_true", help=spec.label, dest=f"scan_{spec.key.replace('-', '_')}")

    # Report Options
    parser.add_argument("--report-json", help="Output JSON report to file")
    parser.add_argument("--report-html", help="Output HTML report to file")

    return parser


def main():
    print_banner()
    parser = build_parser()
    args = parser.parse_args()

    if args.gui:
        print(f"{Fore.GREEN}[*] Please use 'miku-beam --gui' to launch the interface.{Style.RESET_ALL}")
        return

    if not args.url:
        parser.print_help()
        print(f"\n{Fore.RED}[!] Error: Target URL is required.{Style.RESET_ALL}")
        return

    # 1. Initialize Target
    print(f"{Fore.BLUE}[*] Initializing Target: {args.url}{Style.RESET_ALL}")
    target = Target(url=args.url, method=args.method)

    # 2. Setup Authentication
    auth_credentials = {}
    auth_type = AuthType.NONE
    
    if args.auth_type == "bearer" and args.auth_token:
        auth_type = AuthType.BEARER
        auth_credentials = {"token": args.auth_token}
    elif args.auth_type == "basic" and args.auth_user and args.auth_pass:
        auth_type = AuthType.BASIC
        auth_credentials = {"username": args.auth_user, "password": args.auth_pass}
    elif args.auth_type == "api_key" and args.auth_token:
        # Use --auth-token as the API key value; header name defaults to X-API-Key.
        auth_type = AuthType.API_KEY
        auth_credentials = {"key_name": "X-API-Key", "key_value": args.auth_token}

    authenticator = Authenticator(auth_type=auth_type, credentials=auth_credentials)

    # 3. Profiling
    profiler = Profiler(target)
    # Apply auth to profiler session
    authenticator.authenticate(profiler.session)

    # Apply custom headers (JSON) if provided. The scanners reuse profiler.session,
    # so headers set here also apply to the vulnerability-scanning phase.
    if args.headers:
        try:
            profiler.session.headers.update(json.loads(args.headers))
        except (json.JSONDecodeError, ValueError) as e:
            print(f"{Fore.RED}[!] Invalid --headers JSON: {e}{Style.RESET_ALL}")
            return

    profiler.profile()
    
    print_recon_data(target)

    # 4. Scanning
    # Driven by the same registry that generated the --scan-<key> flags above,
    # so a scanner only needs to be added in one place (engine/scanners/registry.py)
    # to become reachable from the CLI. An explicit --scan-<key> always runs that
    # scanner regardless of detected tech (only the automatic/web selection path
    # applies each spec's `applies_to` predicate).
    vulnerabilities = []
    for spec in REGISTRY:
        # Matches the explicit dest= given to add_argument above (rather than
        # relying on argparse's own hyphen-to-underscore dest-mangling, which
        # would silently diverge from this f-string for a future hyphenated key).
        if args.scan_all or getattr(args, f"scan_{spec.key.replace('-', '_')}"):
            logger.info(f"Running {spec.label} scan...")
            scanner = spec.scanner_class(session=profiler.session)
            vulnerabilities.extend(scanner.scan(target))

    # 5. Reporting
    reporter = Reporter(target, vulnerabilities)
    
    if args.report_json:
        reporter.generate_json(args.report_json)
        logger.info(f"JSON report saved to {args.report_json}")
    if args.report_html:
        reporter.generate_html(args.report_html)
        logger.info(f"HTML report saved to {args.report_html}")

    # Print Vulnerability Report to Terminal
    print_vulnerability_report(vulnerabilities)

    logger.info(f"Scan completed. Found {len(vulnerabilities)} total vulnerabilities.")

def print_recon_data(target):
    """Prints enhanced reconnaissance data in a structured format"""
    print(f"\n{Fore.CYAN}{Style.BRIGHT}[+] Reconnaissance Report{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    # 1. Tech Stack
    print(f"\n{Fore.YELLOW}[*] Technology Stack:{Style.RESET_ALL}")
    ts = target.detailed_tech_stack
    if ts:
        print(f"  {Fore.GREEN}Server:{Style.RESET_ALL}   {ts.get('server', 'Unknown')}")
        print(f"  {Fore.GREEN}Backend:{Style.RESET_ALL}  {ts.get('backend', 'Unknown')}")
        print(f"  {Fore.GREEN}Frontend:{Style.RESET_ALL} {ts.get('frontend', 'Unknown')}")
        
        if ts.get('frameworks'):
            print(f"  {Fore.GREEN}Frameworks:{Style.RESET_ALL} {', '.join(ts['frameworks'])}")
        
        if ts.get('languages'):
            print(f"  {Fore.GREEN}Languages:{Style.RESET_ALL}  {', '.join(ts['languages'])}")
    else:
        print("  No detailed tech stack information available.")

    # 2. Open Ports
    if target.open_ports:
        print(f"\n{Fore.YELLOW}[*] Open Ports:{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}{'PORT':<10} {'SERVICE':<15} {'STATE':<10}{Style.RESET_ALL}")
        print(f"  {'-'*35}")
        for port in target.open_ports:
            state_color = Fore.GREEN if port['state'] == 'open' else Fore.RED
            print(f"  {port['port']:<10} {port['service']:<15} {state_color}{port['state']}{Style.RESET_ALL}")

    # 3. Subdomains
    if target.subdomains:
        print(f"\n{Fore.YELLOW}[*] Discovered Subdomains ({len(target.subdomains)}):{Style.RESET_ALL}")
        for sub in target.subdomains[:5]:  # Show first 5
            print(f"  - {sub}")
        if len(target.subdomains) > 5:
            print(f"  ... and {len(target.subdomains) - 5} more")

    # 4. Subdirectories
    if target.subdirectories:
        print(f"\n{Fore.YELLOW}[*] Interesting Directories ({len(target.subdirectories)}):{Style.RESET_ALL}")
        for sub in target.subdirectories[:5]:  # Show first 5
            print(f"  - {sub}")
        if len(target.subdirectories) > 5:
            print(f"  ... and {len(target.subdirectories) - 5} more")
            
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")

def print_vulnerability_report(vulnerabilities):
    """Prints detailed vulnerability report to terminal"""
    if not vulnerabilities:
        return

    print(f"\n{Fore.RED}{Style.BRIGHT}[!] Vulnerability Report ({len(vulnerabilities)} Found){Style.RESET_ALL}")
    print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}")

    for i, vuln in enumerate(vulnerabilities, 1):
        # Determine severity color
        sev_color = Fore.WHITE
        if vuln.severity == "CRITICAL":
            sev_color = Fore.RED + Style.BRIGHT
        elif vuln.severity == "HIGH":
            sev_color = Fore.RED
        elif vuln.severity == "MEDIUM":
            sev_color = Fore.YELLOW
        elif vuln.severity == "LOW":
            sev_color = Fore.BLUE
        
        print(f"\n{Fore.WHITE}[{i}] {sev_color}{vuln.name}{Style.RESET_ALL}")
        print(f"    {Fore.WHITE}Severity:{Style.RESET_ALL}    {sev_color}{vuln.severity}{Style.RESET_ALL}")
        print(f"    {Fore.WHITE}Description:{Style.RESET_ALL} {vuln.description}")
        
        if hasattr(vuln, 'url') and vuln.url:
             print(f"    {Fore.WHITE}URL:{Style.RESET_ALL}         {vuln.url}")
             
        print(f"    {Fore.WHITE}Evidence:{Style.RESET_ALL}    {Fore.CYAN}{vuln.evidence}{Style.RESET_ALL}")

    print(f"\n{Fore.RED}{'='*60}{Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()
