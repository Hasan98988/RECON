import re 
import whois
import argparse
import requests
import socket
import dns.resolver
import tldextract
import sys
import time
import nmap
from bs4 import BeautifulSoup
parser = argparse.ArgumentParser(description='Process site address')
parser.add_argument('url', type=str, help='process as google.com')
args =  parser.parse_args()

def get_links(url):
    # Send a GET request to the URL
    response = requests.get(url)
    
    # Parse the HTML response using BeautifulSoup
    soup = BeautifulSoup(response.text, "html.parser")
    
    # Find all the links on the page
    links = []
    for link in soup.find_all("a"):
        href = link.get("href")
        
        # Ignore links that are not URLs
        if href is not None and href.startswith("http"):
            links.append(href)
    for i in links:
        extracted = tldextract.extract(i)
        domain = extracted.domain
        tld = extracted.suffix
        I=f'{domain}.{tld}'
        #print(i)
        #sub_domian(i)
        #status_url(i)
        #titel_url(i)
        #ip_url(I)
        #nmap_url(I)
        #re_website(i)
        #who_is(I)
        get_links2(i)


def get_links2(links):
  
  response = requests.get(links)
    
  # Parse the HTML response using BeautifulSoup
  soup = BeautifulSoup(response.text, "html.parser")
    
  # Find all the links on the page
  a=0
  linkss = []
  for link2 in soup.find_all("a"):
    href = link2.get("href")
        
    # Ignore links that are not URLs
    if href is not None and href.startswith("http"):
       linkss.append(href)
        # a+= len(linkss)
       for l in linkss:
          extracted = tldextract.extract(l)
          domain = extracted.domain
          tld = extracted.suffix
          L=f'{domain}.{tld}'
          print(l)
          #sub_domian(l)
          #status_url(l)
          #titel_url(l)
          #ip_url(L)
          #nmap_url(L)
          #re_website(l)
          who_is(L)
        

def sub_domian(url):
  extracted = tldextract.extract(url)
  domain = extracted.domain
  tld = extracted.suffix
  find_subdomains = []

  # فایل NS.txt را باز کنید
  with open('NS.txt') as subDom:
    subdoms = subDom.read().splitlines()
    
    # حلقه برای بررسی هر زیر دامنه
    for subdom in subdoms:
        try:
            full_domain = f'{subdom}.{domain}.{tld}'
            ip_value = dns.resolver.resolve(full_domain, 'A')
            if ip_value:
                find_subdomains.append(full_domain)
                print(full_domain)
                ip_url(full_domain)
            time.sleep(1)  # اضافه کردن تاخیر 1 ثانیه‌ای بین هر درخواست
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        except KeyboardInterrupt:
            break

  # چاپ زیر دامنه‌های یافت شده
  for d in find_subdomains:
    print(d)

      
 # domian_url =  pattern.sub(r'\3',link)
 # print(domian_url)
def status_url(url):
     
  # Replace "https://www.example.com" with the URL of the webpage you want to check the status of
  #  url = "https://hackerone.com"

  # Send a GET request to the URL and store the response in a variable
  response = requests.get(url)

  # Check the HTTP status code of the response
  if response.status_code == 200:
    print("Success!")
  elif response.status_code == 404:
    print("Page not found.")
  elif response.status_code == 500:
    print("Internal server error.")
  else:
    print("Unknown status code:", response.status_code)
def titel_url(url):

  # Replace "https://www.example.com" with the URL of the webpage you want to extract the title from
  #url = "https://hackerone.com"

  # Send a GET request to the URL and store the response in a variable
  response = requests.get(url)

  # Use Beautiful Soup to parse the HTML content of the response
  soup = BeautifulSoup(response.content, 'html.parser')

  # Extract the title of the webpage using the 'title' tag
  title = soup.title.string

  print(title)
def ip_url(domain):
  ip_address = socket.gethostbyname(domain)

  print(f'The IP address of {domain} is {ip_address}')
  

def nmap_url(domain):
  ip = socket.gethostbyname(domain)

  
    # Replace with the IP address you want to scan

  nm = nmap.PortScanner()
  nm.scan(ip, arguments="-p 1-535 -T4")  # Scan all ports (1-65535) with aggressive timing (-T4)

  for host in nm.all_hosts():
      print("Open ports for {}:".format(host))
      for port in nm[host]["tcp"].keys():
          if nm[host]["tcp"][port]["state"] == "open":
              print("Port {} is open".format(port))
          
              
def re_website(url):
 
  # دریافت HTML
  response = requests.get(url)
  html_content = BeautifulSoup(response.text, "html.parser").get_text()

  # الگوی regex برای شماره تلفن‌های همراه ایرانی
  mobile_pattern = r'\b(?:0|\+98|0098)?9\d{9}\b'

  # الگوی regex برای شماره تلفن‌های ثابت ایرانی
  landline_pattern = r'\b(?:0)?(21|26|25|31|41|51)\d{8}\b'

  # الگوی regex برای ایمیل‌ها
  email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

  # ترکیب سه الگو با هم
  combined_pattern = f"({mobile_pattern})|({landline_pattern})|({email_pattern})"

  # استخراج ایمیل‌ها و شماره تلفن‌ها
  matches = re.findall(combined_pattern, html_content)

  # استخراج داده‌ها به صورت لیست
  extracted_data = [match for group in matches for match in group if match]

  # نمایش نتایج
  print("Extracted data:", extracted_data)


def who_is(domain):
  w = whois.whois(domain)

  print(w)



get_links(args.url)




