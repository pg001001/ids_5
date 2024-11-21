#!/bin/bash

# Check if domain is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

# Function to scan for JavaScript files, download them, and search for sensitive information
scan_information() {
    local domain=$1
    local base_dir="${domain}"
    mkdir -p "${base_dir}"
    mkdir -p "${base_dir}/information/"

    # javaScript files
    echo "Scanning for JavaScript files on ${domain}..."
    mkdir -p "${base_dir}/js_files/"  && xargs -a "${base_dir}/js.txt" -I {} wget -q {} -P "${base_dir}/js_files/"
    cat "${base_dir}/allurls.txt" | grep "\.js$"  "${base_dir}/allurls.txt" | httpx -mc 200 | tee "${base_dir}/js.txt"

    # sensitive information in downloaded JavaScript files
    echo "Searching for sensitive information in JavaScript files..."
    grep -r --color=always -i -E "api_key|apikey|aws" "${base_dir}/js_files/" | tee "${base_dir}/information/js.txt"
    
    # api spicific endpoints
    # katana -mdc "contains(endpoint,"api")" -jc -u ${domain} >> "${base_dir}/information/api_endpoints.txt"
    grep -r --color=always -i -E "api|\.env|\.config" "${base_dir}/allurls.txt" >> "${base_dir}/information/api_endpoints.txt"

    # emails
    grep -r --color=always -i -E "@" "${base_dir}/allurls.txt" >> "${base_dir}/information/emails.txt"
    grep -r --color=always -i -E "%40" "${base_dir}/allurls.txt" >> "${base_dir}/information/emails.txt"
    grep -r --color=always -i -E "gmail|yahoo|hotmail|outlook" "${base_dir}/allurls.txt" >> "${base_dir}/information/common_emails.txt"

    # billngs
    grep -r --color=always -i -E "invoice|billing|payment|receipt|bill|purchase|order|checkout|transaction" "${base_dir}/allurls.txt" >> "${base_dir}/information/pay.txt"

    # credentials
    grep -r --color=always -i -E "register:|signin:|signup:|login:" "${base_dir}/allurls.txt" >> "${base_dir}/information/credentials.txt"

    # search sensitive files 
    grep -r --color=always -i -E "\.sql|\.zip|\.tar.gz|\.tgz|\.bak|\.7z|\.rar" "${base_dir}/allurls.txt" >> "${base_dir}/information/files.txt"
    grep -r --color=always -i -E "\.pdf" "${base_dir}/allurls.txt" >> "${base_dir}/information/pdfs.txt"
    grep -r --color=always -i -E ".\xlsx|\.doc|\.docx|\.pptx|\.xls" "${base_dir}/allurls.txt" >> "${base_dir}/information/documents.txt"
    
    # admin panels
    grep -r --color=always -i -E "admin" "${base_dir}/subdomains.txt" >> "${base_dir}/information/admin_panels.txt"

    # get parameters 
    # gau -subs ${domain} | grep -oP "(\?|\&)\w+" | tr -d "?|&" | sort -u | tee params.txt





}

# Run the JS scan function with the provided domain
scan_information "$1"
