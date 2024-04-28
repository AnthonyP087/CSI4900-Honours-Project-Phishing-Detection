"""
%pip install python-whois
%pip install dnspython
%pip install pandas
%pip install tranco
%pip install requests
%pip install socket
%pip install tld
"""
import sys
import joblib
import warnings

from sklearn.inspection import permutation_importance
from sklearn.metrics import accuracy_score, classification_report, matthews_corrcoef

warnings.filterwarnings("ignore")
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import dns.resolver
import numpy as np
import pandas as pd
from tranco import Tranco
import requests
import re
from bs4 import BeautifulSoup
import whois
from urllib.parse import urlparse
from urllib.parse import parse_qs
from tld import get_tld
from datetime import datetime
import socket
import time
import ssl

t = Tranco(cache=True, cache_dir='.tranco')
latest_list = t.list()
pd.set_option('display.max_columns', None)  # All columns when doing head()


def qty_dot_url(url):
    x = url.count('.')
    return x


def qty_hyphen_url(url):
    x = url.count('-')
    return x


def qty_underline_url(url):
    x = url.count('_')
    return x


def qty_slash_url(url):
    x = url.count('/')
    return x


def qty_questionmark_url(url):
    x = url.count('?')
    return x


def qty_equal_url(url):
    x = url.count('=')
    return x


def qty_at_url(url):
    x = url.count('@')
    return x


def qty_and_url(url):
    x = url.count('&')
    return x


def qty_exclamation_url(url):
    x = url.count('!')
    return x


def qty_space_url(url):
    x = url.count(' ')
    return x


def qty_tilde_url(url):
    x = url.count('~')
    return x


def qty_comma_url(url):
    x = url.count(',')
    return x


def qty_plus_url(url):
    x = url.count('+')
    return x


def qty_asterisk_url(url):
    x = url.count('*')
    return x


def qty_hashtag_url(url):
    x = url.count('#')
    return x


def qty_dollar_url(url):
    x = url.count('$')
    return x


def qty_percent_url(url):
    x = url.count('%')
    return x


# top level domain length
def qty_tld_url(url):
    x = get_tld(url, fail_silently=True)
    if x is None:
        return 0
    else:
        return len(x)


def length_url(url):
    return len(url)


def qty_dot_domain(domain):
    x = domain.count('.')
    return x


def qty_hyphen_domain(domain):
    x = domain.count('-')
    return x


def qty_underline_domain(domain):
    x = domain.count('_')
    return x


def qty_slash_domain(domain):
    x = domain.count('/')
    return x


def qty_questionmark_domain(domain):
    x = domain.count('?')
    return x


def qty_equal_domain(domain):
    x = domain.count('=')
    return x


def qty_at_domain(domain):
    x = domain.count('@')
    return x


def qty_and_domain(domain):
    x = domain.count('&')
    return x


def qty_exclamation_domain(domain):
    x = domain.count('!')
    return x


def qty_space_domain(domain):
    x = domain.count(' ')
    return x


def qty_tilde_domain(domain):
    x = domain.count('~')
    return x


def qty_comma_domain(domain):
    x = domain.count(',')
    return x


def qty_plus_domain(domain):
    x = domain.count('+')
    return x


def qty_asterisk_domain(domain):
    x = domain.count('*')
    return x


def qty_hashtag_domain(domain):
    x = domain.count('#')
    return x


def qty_dollar_domain(domain):
    x = domain.count('$')
    return x


def qty_percent_domain(domain):
    x = domain.count('%')
    return x


def qty_vowels_domain(domain):
    vowels = 'aeiouAEIOU'
    return sum(1 for char in domain if char in vowels)


def domain_length(domain):
    return len(domain)


def domain_in_ip(domain):
    r = re.search(
        '^http[s]?:\/\/((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])',
        domain)
    if r:
        return 1
    else:
        return 0


def server_client_domain(domain):
    r = re.search('server', domain)
    r2 = re.search('client', domain)
    if (r or r2):
        return 1
    else:
        return 0


def qty_dot_directory(directory):
    x = directory.count('.')
    return x


def qty_hyphen_directory(directory):
    x = directory.count('-')
    return x


def qty_underline_directory(directory):
    x = directory.count('_')
    return x


def qty_slash_directory(directory):
    x = directory.count('/')
    return x


def qty_questionmark_directory(directory):
    x = directory.count('?')
    return x


def qty_equal_directory(directory):
    x = directory.count('=')
    return x


def qty_at_directory(directory):
    x = directory.count('@')
    return x


def qty_and_directory(directory):
    x = directory.count('&')
    return x


def qty_exclamation_directory(directory):
    x = directory.count('!')
    return x


def qty_space_directory(directory):
    x = directory.count(' ')
    return x


def qty_tilde_directory(directory):
    x = directory.count('~')
    return x


def qty_comma_directory(directory):
    x = directory.count(',')
    return x


def qty_plus_directory(directory):
    x = directory.count('+')
    return x


def qty_asterisk_directory(directory):
    x = directory.count('*')
    return x


def qty_hashtag_directory(directory):
    x = directory.count('#')
    return x


def qty_dollar_directory(directory):
    x = directory.count('$')
    return x


def qty_percent_directory(directory):
    x = directory.count('%')
    return x


def directory_length(directory):
    return len(directory)


def qty_dot_file(file):
    x = file.count('.')
    return x


def qty_hyphen_file(file):
    x = file.count('-')
    return x


def qty_underline_file(file):
    x = file.count('_')
    return x


def qty_slash_file(file):
    x = file.count('/')
    return x


def qty_questionmark_file(file):
    x = file.count('?')
    return x


def qty_equal_file(file):
    x = file.count('=')
    return x


def qty_at_file(file):
    x = file.count('@')
    return x


def qty_and_file(file):
    x = file.count('&')
    return x


def qty_exclamation_file(file):
    x = file.count('!')
    return x


def qty_space_file(file):
    x = file.count(' ')
    return x


def qty_tilde_file(file):
    x = file.count('~')
    return x


def qty_comma_file(file):
    x = file.count(',')
    return x


def qty_plus_file(file):
    x = file.count('+')
    return x


def qty_asterisk_file(file):
    x = file.count('*')
    return x


def qty_hashtag_file(file):
    x = file.count('#')
    return x


def qty_dollar_file(file):
    x = file.count('$')
    return x


def qty_percent_file(file):
    x = file.count('%')
    return x


def file_length(file):
    return len(file)


def qty_dot_params(params):
    x = params.count('.')
    return x


def qty_hyphen_params(params):
    x = params.count('-')
    return x


def qty_underline_params(params):
    x = params.count('_')
    return x


def qty_slash_params(params):
    x = params.count('/')
    return x


def qty_questionmark_params(params):
    x = params.count('?')
    return x


def qty_equal_params(params):
    x = params.count('=')
    return x


def qty_at_params(params):
    x = params.count('@')
    return x


def qty_and_params(params):
    x = params.count('&')
    return x


def qty_exclamation_params(params):
    x = params.count('!')
    return x


def qty_space_params(params):
    x = params.count(' ')
    return x


def qty_tilde_params(params):
    x = params.count('~')
    return x


def qty_comma_params(params):
    x = params.count(',')
    return x


def qty_plus_params(params):
    x = params.count('+')
    return x


def qty_asterisk_params(params):
    x = params.count('*')
    return x


def qty_hashtag_params(params):
    x = params.count('#')
    return x


def qty_dollar_params(params):
    x = params.count('$')
    return x


def qty_percent_params(params):
    x = params.count('%')
    return x


def params_length(params):
    return len(params)


def tld_present_params(params):
    if params is None:
        return -1
    x = get_tld(params, fail_silently=True)
    if x is None:
        return 0
    else:
        return 1


# count number of parameters in url
def qty_params(url):
    x = 0
    for param in parse_qs(url):
        x = x + 1
    return x


def email_in_url(url):
    return 1 if re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', url) is not None else 0


def time_response(domain):
    dns_start = time.time()
    try:
        ip = socket.gethostbyname(domain)
    except:
        return 0;
    dns_end = time.time()
    return dns_end - dns_start


def domain_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_data = rdata.strings
            for txt_string in txt_data:
                if txt_string.startswith('v=spf1'):
                    return 1  # SPF record found
        return 0  # No SPF record found
    except dns.resolver.NoAnswer:
        return 0  # No TXT records found
    except dns.resolver.NXDOMAIN:
        return 0  # Domain doesn't exist
    except Exception:
        return -1  # Any other error


def asn_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        response = requests.get(f'https://api.hackertarget.com/aslookup/?q={ip}')
        if response.status_code == 200:
            # Split the response text by commas and extract the second field
            fields = response.text.split(",")
            if len(fields) > 1:
                return int(fields[1].strip('"'))  # Return the second field as an integer
            else:
                print("Unexpected response format")
                return 0
        else:
            print("Request failed with status code:", response.status_code)
            return -1
    except Exception as e:
        return -1


def time_domain_activation(record):
    try:
        if record is not None:
            if ((record.creation_date is not None) & (isinstance(record.creation_date, list))):
                return (datetime.now() - record.creation_date[0]).days
            elif (record.creation_date is not None):
                return (datetime.now() - record.creation_date).days
            else:
                return 0
        else:
            return 0
    except:
        return 0


def time_domain_expiration(record):
    try:
        if record is not None:
            if ((record.expiration_date is not None) & (isinstance(record.expiration_date, list))):
                return (record.expiration_date[0] - datetime.now()).days
            elif (record.expiration_date is not None):
                return (record.expiration_date - datetime.now()).days
            else:
                return 0
        else:
            return 0
    except:
        return 0


def qty_ip_resolved(domain):
    try:
        ips = socket.getaddrinfo(domain, None)
        qty_ips = len(set([ip[4][0] for ip in ips]))
        return qty_ips
    except socket.gaierror as e:
        print("Error:", e)
        return -1


def qty_nameservers(domain):
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        ns_count = len(answers)
        return ns_count
    except dns.resolver.NoAnswer:
        return 0  # No NS records found
    except dns.resolver.NXDOMAIN:
        return 0  # Domain doesn't exist
    except dns.resolver.NoNameservers:
        return 0  # No nameservers found for the domain
    except Exception as e:
        print(f"An error occurred: {e}")
        return -1  # Return -1 if there's an error


def qty_mx_servers(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_count = len(answers)
        return mx_count
    except dns.resolver.NoAnswer:
        return 0  # No MX records found
    except dns.resolver.NXDOMAIN:
        return 0  # Domain doesn't exist
    except dns.resolver.NoNameservers:
        return 0  # No nameservers found for the domain
    except Exception as e:
        print(f"An error occurred: {e}")
        return -1  # Return -1 if there's an error


def ttl_hostname(domain):
    try:
        answers = dns.resolver.resolve(domain)
        ttl = answers.rrset.ttl
        return ttl
    except dns.resolver.NoAnswer:
        return 0  # No answer found
    except dns.resolver.NXDOMAIN:
        return 0  # Domain doesn't exist
    except dns.resolver.NoNameservers:
        return 0  # No nameservers found for the domain
    except Exception as e:
        print(f"An error occurred: {e}")
        return -1  # Return -1 if there's an error


def tls_ssl_certificate(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return 1  # Certificate is valid
    except ssl.CertificateError:
        return 0  # Certificate is invalid
    except Exception as e:
        print(f"An error occurred: {e}")
        return 0  # Certificate is invalid due to error


def qty_redirects(url):
    try:
        response = requests.head(url, allow_redirects=True, timeout=60)
        return len(response.history)
    except requests.RequestException as e:
        print("An error occurred:", e)
        return -1  # Return -1 if there's an error


def url_google_index(url):
    google = "https://www.google.com/search?q=site:" + url + "&hl=en"
    response = requests.get(google, cookies={"CONSENT": "YES+1"})
    soup = BeautifulSoup(response.content, "html.parser")
    not_indexed = re.compile("did not match any documents")
    if soup(text=not_indexed):
        return 0
    else:
        return 1


def domain_google_index(domain):
    google = "https://www.google.com/search?q=site:" + domain + "&hl=en"
    response = requests.get(google, cookies={"CONSENT": "YES+1"})
    soup = BeautifulSoup(response.content, "html.parser")
    not_indexed = re.compile("did not match any documents")
    if soup(text=not_indexed):
        return 0
    else:
        return 1


shortening_services = {
    '3.ly', 'bit.ly', 'bitly.kr', 'bl.ink', 'buff.ly', 'clicky.me', 'cutt.ly',
    'Dub.co', 'fox.ly', 'gg.gg', 'han.gl', 'hoy.kr', 'is.gd', 'KurzeLinks.de',
    'kutt.it', 'LinkHuddle', 'LinkSplit', 'lstu.fr', 'name.com', 'oe.cd', 'Ow.ly',
    'rebrandly.com', 'rip.to', 'san.aq', 'short.io', 'shorturl.at', 'smallseotools',
    'spoo.me', 'switchy.io', 'T2M', 'tinu.be', 'Tiny URL', 'T.LY', 'urlr.me',
    'v.gd', 'vo.la'
}  # Credit to https://github.com/738/awesome-url-shortener


def url_shortened(url):
    url_lower = url.lower()
    return 1 if any(service.lower() in url_lower for service in shortening_services) else 0


def url_parser(url):
  if not urlparse(url).scheme:
    url = "https://" + url
  return urlparse(url)

def validateURL(url):
    regex = "^((http|https)://)[-a-zA-Z0-9@:%._\\+~#?&//=]{2,256}\\.[a-z]{2,6}\\b([-a-zA-Z0-9@:%._\\+~#?&//=]*)$"
    r = re.compile(regex)
    if (re.search(r, url)):
      return 1
    else:
      return 0

def qty_special_chars_url(url):
  return len(re.findall(r'[^a-zA-Z0-9]', url))

def ratio_special_chars_url(url):
  return qty_special_chars_url(url) / length_url(url)

def qty_special_chars_domain(domain):
  return len(re.findall(r'[^a-zA-Z0-9]', domain))

def ratio_special_chars_domain(domain):
  return qty_special_chars_domain(domain) / domain_length(domain)


def featureExtraction(url):
    if validateURL(url) == 0:
      return "Not a valid URL"
    parsed = url_parser(url)
    domain = parsed.netloc
    directory = parsed.path.rsplit("/", 1)[0]
    file = parsed.path.rsplit("/", 1)[-1]
    params = parsed.query
    try:
      record = whois.whois(domain)
    except:
      record = None
    features = []
    features.append(qty_dot_url(url))
    features.append(qty_hyphen_url(url))
    features.append(qty_underline_url(url))
    features.append(qty_slash_url(url))
    features.append(qty_questionmark_url(url))
    features.append(qty_equal_url(url))
    features.append(qty_at_url(url))
    features.append(qty_and_url(url))
    features.append(qty_exclamation_url(url))
    features.append(qty_space_url(url))
    features.append(qty_tilde_url(url))
    features.append(qty_comma_url(url))
    features.append(qty_plus_url(url))
    features.append(qty_asterisk_url(url))
    features.append(qty_hashtag_url(url))
    features.append(qty_dollar_url(url))
    features.append(qty_percent_url(url))
    features.append(qty_tld_url(url))
    features.append(length_url(url))
    features.append(qty_dot_domain(domain))
    features.append(qty_hyphen_domain(domain))
    features.append(qty_underline_domain(domain))
    features.append(qty_slash_domain(domain))
    features.append(qty_questionmark_domain(domain))
    features.append(qty_equal_domain(domain))
    features.append(qty_at_domain(domain))
    features.append(qty_and_domain(domain))
    features.append(qty_exclamation_domain(domain))
    features.append(qty_space_domain(domain))
    features.append(qty_tilde_domain(domain))
    features.append(qty_comma_domain(domain))
    features.append(qty_plus_url(domain))
    features.append(qty_asterisk_domain(domain))
    features.append(qty_hashtag_domain(domain))
    features.append(qty_dollar_domain(domain))
    features.append(qty_percent_domain(domain))
    features.append(qty_vowels_domain(domain))
    features.append(domain_length(domain))
    features.append(domain_in_ip(domain))
    features.append(server_client_domain(domain))
    features.append(qty_dot_directory(directory))
    features.append(qty_hyphen_directory(directory))
    features.append(qty_underline_directory(directory))
    features.append(qty_slash_directory(directory))
    features.append(qty_questionmark_directory(directory))
    features.append(qty_equal_directory(directory))
    features.append(qty_at_directory(directory))
    features.append(qty_and_directory(directory))
    features.append(qty_exclamation_directory(directory))
    features.append(qty_space_directory(directory))
    features.append(qty_tilde_directory(directory))
    features.append(qty_comma_directory(directory))
    features.append(qty_plus_directory(directory))
    features.append(qty_asterisk_directory(directory))
    features.append(qty_hashtag_directory(directory))
    features.append(qty_dollar_directory(directory))
    features.append(qty_percent_directory(directory))
    features.append(directory_length(directory))
    features.append(qty_dot_file(file))
    features.append(qty_hyphen_file(file))
    features.append(qty_underline_file(file))
    features.append(qty_slash_file(file))
    features.append(qty_questionmark_file(file))
    features.append(qty_equal_file(file))
    features.append(qty_at_file(file))
    features.append(qty_and_file(file))
    features.append(qty_exclamation_file(file))
    features.append(qty_space_file(file))
    features.append(qty_tilde_file(file))
    features.append(qty_comma_file(file))
    features.append(qty_plus_file(file))
    features.append(qty_asterisk_file(file))
    features.append(qty_hashtag_file(file))
    features.append(qty_dollar_file(file))
    features.append(qty_percent_file(file))
    features.append(file_length(file))
    features.append(qty_dot_params(params))
    features.append(qty_hyphen_params(params))
    features.append(qty_underline_params(params))
    features.append(qty_slash_params(params))
    features.append(qty_questionmark_params(params))
    features.append(qty_equal_params(params))
    features.append(qty_at_params(params))
    features.append(qty_and_params(params))
    features.append(qty_exclamation_params(params))
    features.append(qty_space_params(params))
    features.append(qty_tilde_params(params))
    features.append(qty_comma_params(params))
    features.append(qty_plus_params(params))
    features.append(qty_asterisk_params(params))
    features.append(qty_hashtag_params(params))
    features.append(qty_dollar_params(params))
    features.append(qty_percent_params(params))
    features.append(params_length(params))
    features.append(tld_present_params(params))
    features.append(qty_params(params))
    features.append(email_in_url(url))
    features.append(time_response(domain))
    features.append(domain_spf(domain))
    features.append(asn_ip(domain))
    features.append(time_domain_activation(record))
    features.append(time_domain_expiration(record))
    features.append(qty_ip_resolved(domain))
    features.append(qty_nameservers(domain))
    features.append(qty_mx_servers(domain))
    features.append(ttl_hostname(domain))
    features.append(tls_ssl_certificate(domain))
    features.append(qty_redirects(url))
    features.append(url_google_index(url))
    features.append(domain_google_index(url))
    features.append(url_shortened(url))
    features.append(qty_special_chars_url(url))
    features.append(ratio_special_chars_url(url))
    features.append(qty_special_chars_domain(domain))
    features.append(ratio_special_chars_domain(domain))
    return features

url = 'https://drive.google.com/file/d/1VOX_lwKteAhRzC-zalToE-AM6B6Mp8KL/view?usp=sharing'
url = 'https://drive.google.com/uc?id=' + url.split('/')[-2]
data = pd.read_csv(url)

nulldata = data.isnull().sum()
data = data.fillna(0)
nulldata[nulldata > 0]

y = data['phishing']
x = data.drop(columns='phishing', axis=1)
RandomForest2 = RandomForestClassifier(oob_score=True, n_jobs=-1, random_state=42, max_features=200, n_estimators=60)
X_train, X_test, y_train, y_test = train_test_split(x, y, test_size=0.20, random_state=1)
RandomForest2.fit(X_train, y_train)
y_pred = RandomForest2.predict(X_test)
acc = accuracy_score(y_pred, y_test)
testbruh = np.array([featureExtraction("https://zendesk.com")])
test3 = RandomForest2.predict(testbruh)
print("result is: ", test3)

"""
#save the model to disk
filename = 'RandomForestMaliciousLinksArray.joblib'
joblib.dump(resultmalfeatures, filename)

filename = 'RandomForestSafeLinksArray.joblib'
joblib.dump(resultvalfeatures, filename)

#wait to load...


#load the model from disk
loaded_model = joblib.load(filename)
model_size = sys.getsizeof(loaded_model)
print("size of the loaded model: ", model_size, "bytes")
result = loaded_model.score(X_test, y_test)
print("score of loaded model: ", result)
testbruh2 = np.array([featureExtraction("https://zendesk.com")])
loadedModelTest = loaded_model.predict(testbruh)
print("result is: ", loadedModelTest)
"""