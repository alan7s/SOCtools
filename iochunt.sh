#!/bin/bash
#IoC Hunt
#Version v0.2 by alan7s
#Tools needed:
#[+] nslookup
#[+] HEDnsExtractor (https://github.com/HuntDownProject/HEDnsExtractor)
#[+] httpx (https://docs.projectdiscovery.io/tools/httpx/install)

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <url> <string>"
    exit 1
fi

url=$1
str=$2

domain=$(echo "$url" | awk -F/ '{print $1}')
path=$(echo "$url" | awk -F"$domain" '{print $2}')

if [ -z "$path" ]; then
    path="/"
fi

echo "Working..."

nslookup "$domain" | awk '/Address: / {print $2}' | hednsextractor -silent -only-domains | httpx -path "$path" -mc 200 -silent -ms "$str"  | tee -a iocs.txt

echo "Check your output in iocs.txt"
