import requests

def search_vulnerabilities(vendor_name, max_results=10):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        'keywordSearch': vendor_name,
        'resultsPerPage': max_results
    }
    
    # Add keywordExactMatch if vendor_name contains more than one term
    if ' ' in vendor_name:
        params['keywordExactMatch'] = ''
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36'
    }

    response = requests.get(base_url, params=params, headers=headers)
    if response.status_code == 200:
        vulnerabilities = response.json().get('vulnerabilities', [])
        return vulnerabilities
    else:
        print(f"Error: Unable to fetch data (status code {response.status_code})")
        return []

def print_vulnerabilities(vulnerabilities):
    if not vulnerabilities:
        print("No vulnerabilities found or an error occurred.")
        return
    
    for vuln in vulnerabilities:
        cve_id = vuln.get('cve', {}).get('id')
        descriptions = vuln.get('cve', {}).get('descriptions', [])
        description = descriptions[0].get('value') if descriptions else "No description available"
        print(f"CVE ID: {cve_id}")
        print(f"Description: {description}")
        print("-" * 80)

if __name__ == "__main__":
    vendor = "Xiaomi Mi Mix 2"
    vulnerabilities = search_vulnerabilities(vendor)
    print_vulnerabilities(vulnerabilities)