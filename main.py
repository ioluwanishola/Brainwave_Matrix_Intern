# Import the tldextract library to extract domain parts from URLs
import tldextract

# Import the Levenshtein library to calculate string similarity
import Levenshtein as lv

# Define a list of legitimate domains to compare against
legitimate_domains = ['exampple.come', 'google.com', 'facebook.com']

# Define a list of test URLs to check for potential phishing
test_urls = [
    'https://www.google.com',  # Legitimate Google domain
    'https://facebook.com',   # Legitimate Facebook domain
    'https://facebooks.com',  # Misspelled Facebook domain
    'https://www.facebook.com.hacker-site.com',  # Suspicious subdomain
    'https://www.google.secure-login.com',  # Suspicious subdomain
]

# Function to extract subdomain, domain, and suffix from a URL
def extract_domain_parts(url):
    # Use tldextract to extract the domain parts
    extracted = tldextract.extract(url)
    # Return the subdomain, domain, and suffix
    return extracted.subdomain, extracted.domain, extracted.suffix

# Function to check if a domain is misspelled compared to legitimate domains
def is_misspelled_domain(domain, legitimate_domains, threshold=0.9):
    # Iterate through each legitimate domain
    for legit_domain in legitimate_domains:
        # Calculate the similarity between the domain and the legitimate domain
        similarity = lv.ratio(domain, legit_domain)
        # If the similarity is above the threshold, the domain is not misspelled
        if similarity >= threshold:
            return False  # It's a legitimate domain
    # If no close match is found, the domain is potentially misspelled
    return True  # No close match found, possibly misspelled

# Function to check if a URL is potentially a phishing URL
def is_phishing_url(url, legitimate_domains):
    # Extract the subdomain, domain, and suffix from the URL
    subdomain, domain, suffix = extract_domain_parts(url)

    # Check if the domain and suffix match a known legitimate domain
    if f"{domain}.{suffix}" in legitimate_domains:
        return False  # It's a legitimate domain, not phishing
    
    # Check if the domain is misspelled compared to legitimate domains
    if is_misspelled_domain(domain, legitimate_domains):
        # Print a warning if the domain is potentially misspelled
        print(f"Potential Phishing detected: {url}")
        return True  # It's potentially a phishing URL
    
    # If no issues are found, it's not a phishing URL
    return False

# Main block to execute the script
if __name__ == '__main__':
    # Iterate through each URL in the test_urls list
    for url in test_urls:
        # Check if the URL is potentially a phishing URL
        is_phishing_url(url, legitimate_domains)