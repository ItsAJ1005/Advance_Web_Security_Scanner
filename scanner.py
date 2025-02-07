import click
from attacks.injection.sql_injection import SQLInjectionScanner
from attacks.xss.reflected_xss import ReflectedXSSScanner

@click.group()
def cli():
    """Web Vulnerability Scanner CLI"""
    pass

@cli.command()
@click.argument('target_url')
@click.option('--scan-type', 
              type=click.Choice(['sql', 'xss', 'all']), 
              default='all')
def scan(target_url, scan_type):
    """Perform web vulnerability scanning"""
    scanners = {
        'sql': SQLInjectionScanner,
        'xss': ReflectedXSSScanner
    }

    if scan_type == 'all':
        for scanner_class in scanners.values():
            scanner = scanner_class(target_url)
            scanner.scan()
    else:
        scanner = scanners[scan_type](target_url)
        scanner.scan()

if __name__ == '__main__':
    cli()