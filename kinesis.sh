#!/bin/bash
touch /tmp/score.json # score json file which will be stuffed in html later

# json manipulation functions
# in the end, json looks like {header:{title:"title", inject:false, timestamp:"..."}, vulns:[{name:"vuln", points:5},null,...]}
_header() {
    local title="$1"
    local injectbool="$2"
    local date=$(date)
    echo -n "{\"header\":{\"title\":\"$title\", \"inject\":$injectbool, \"timestamp\":\"$date\"}, \"vulns\":[" >> /tmp/score.json
}

_append_found() {
    local vuln_name="$1"
    local points="$2"

    echo -n "{\"name\":\"$vuln_name\", \"points\":$points}," >> /tmp/score.json
}

_append_unsolved() {
    echo -n "null," >> /tmp/score.json
}

_terminate(){
    local template_html_file="$1"
    local html_file="$2"

    # reset html file with template
    cat "$template_html_file" > "$html_file" 
    # remove the trailing comma
    sed -i 's/,\([^,]*\)$/ \1/' /tmp/score.json
    # close brackets
    echo "]}" >> /tmp/score.json
    # stuff raw json into html because CORS prevents reading of local files in JS
    sed -i -e "/<!--JSONHERE-->/r /tmp/score.json" -e "/<!--JSONHERE-->/d" "$html_file"

    rm /tmp/score.json
}

# Function to check if text exists in a file
check_text_exists() {
    local file="$1"
    local text="$2"
    local vuln_name="$3"
    local points="$4"
    
    if grep -q "$text" "$file"; then
        echo "Vulnerability fixed: '$vuln_name'"
        _append_found "$vuln_name" "$points"
    else
        echo "Unsolved Vuln"
        _append_unsolved
    fi
}
check_text_exists2() {
    local file="$1"
    local text="$2"
    local text2="$3"
    local vuln_name="$4"
    local points="$5"
    
    if grep -q "$text" "$file" && grep -q "$text2" "$file"; then
        echo "Vulnerability fixed: '$vuln_name'"
        _append_found "$vuln_name" "$points"
    else
        echo "Unsolved Vuln"
        _append_unsolved
    fi
}
check_text_exists3() {
    local file="$1"
    local text="$2"
    local text2="$3"
    local text3="$4"
    local vuln_name="$5"
    local points="$6"
    
    if grep -q "$text" "$file" && grep -q "$text2" "$file" && grep -q "$text3" "$file"; then
        echo "Vulnerability fixed: '$vuln_name'"
        _append_found "$vuln_name" "$points"
    else
        echo "Unsolved Vuln"
        _append_unsolved
    fi
}

# Function to check if text does not exist in a file
check_text_not_exists() {
    local file="$1"
    local text="$2"
    local vuln_name="$3"
    local points="$4"
    
    if ! grep -q "$text" "$file"; then
        echo "Vulnerability fixed: '$vuln_name'"
        _append_found "$vuln_name" "$points"
    else
        echo "Unsolved Vuln"
        _append_unsolved
    fi
}
check_text_not_exists2() {
    local file="$1"
    local text="$2"
    local text2="$3"
    local vuln_name="$4"
    local file2="$5"
    local points="$6"
    
    if ! grep -q "$text" "$file" && ! grep -q "$text2" "$file2"; then
        echo "Vulnerability fixed: '$vuln_name'"
        _append_found "$vuln_name" "$points"
    else
        echo "Unsolved Vuln"
        _append_unsolved
    fi
}
# Function to check if a file exists
check_file_exists() {
    local file="$1"
    local vuln_name="$2"
    local points="$3"
    
    if [ -e "$file" ]; then
        echo "Vulnerability fixed: '$vuln_name'"
        _append_found "$vuln_name" "$points"
    else
        echo "Unsolved Vuln"
        _append_unsolved
    fi
}

# Function to check if a file has been deleted
check_file_deleted() {
    local file="$1"
    local vuln_name="$2"
    local points="$3"
    
    if [ ! -e "$file" ]; then
        echo "Vulnerability fixed: '$vuln_name'"
        _append_found "$vuln_name" "$points"
    else
        echo "Unsolved Vuln"
        _append_unsolved
    fi
}
check_file_deleted2() {
    local file="$1"
    local file2="$2"
    local vuln_name="$3"
    local points="$4"
    
    if ! -e "$file" && ! -e "$file2"; then
        echo "Vulnerability fixed: '$vuln_name'"
        _append_found "$vuln_name" "$points"
    else
        echo "Unsolved Vuln"
        _append_unsolved
    fi
}
check_file_deleted3() {
    local file="$1"
    local file2="$2"
    local file3="$3"
    local vuln_name="$4"
    local points="$5"
    
    if ! -e "$file" && ! -e "$file2" && ! -e "$file3"; then
        echo "Vulnerability fixed: '$vuln_name'"
        _append_found "$vuln_name" "$points"
    else
        echo "Unsolved Vuln"
        _append_unsolved
    fi
}
check_file_permissions() {
    local file="$1"
    local expected_permissions="$2"
    local vuln_name="$3"
    local points="$4"
    
    
    # Get the actual permissions of the file in numeric form (e.g., 644)
    actual_permissions=$(stat -c "%a" "$file")
    
    if [ "$actual_permissions" == "$expected_permissions" ]; then
        echo "Vulnerability fixed: '$vuln_name'"
        _append_found "$vuln_name" "$points"
    else
        echo "Unsolved Vuln"
        _append_unsolved
    fi
}

check_file_ownership() { # Thanks Coyne <3
    local file="$1"
    local expected_owner="$2"
    local vuln_name="$3"
    local points="$4"
    
     if getfacl "$file" 2>/dev/null | grep -q "owner: $expected_owner"; then
        echo "Vulnerability fixed: '$vuln_name'"
        _append_found "$vuln_name" "$points"
    else
        echo "Unsolved Vuln"
        _append_unsolved
    fi
}

check_packages() {
    local package="$1"
    local vuln_name="$2"
    local points="$3"
    

    if ! dpkg --get-selections | grep -q "^$package[[:space:]]*install$"; then
        echo "Vulnerability fixed: '$vuln_name'"
        _append_found "$vuln_name" "$points"
    else
        echo "Unsolved Vuln"
        _append_unsolved
    fi
}
check_packages2() {
    local package="$1"
    local package2="$2"
    local vuln_name="$3"
    local points="$4"
    

    if ! dpkg --get-selections | grep -q "^$package[[:space:]]*install$" && ! dpkg --get-selections | grep -q "^$package2[[:space:]]*install$"; then
        echo "Vulnerability fixed: '$vuln_name'"
        _append_found "$vuln_name" "$points"
    else
        echo "Unsolved Vuln"
        _append_unsolved
    fi
}

check_packages3() {
    local package="$1"
    local package2="$2"
    local package3="$3"
    local vuln_name="$4"
    local points="$5"
    

    if ! dpkg --get-selections | grep -q "^$package[[:space:]]*install$" && ! dpkg --get-selections | grep -q "^$package2[[:space:]]*install$" && ! dpkg --get-selections | grep -q "^$package3[[:space:]]*install$"; then
        echo "Vulnerability fixed: '$vuln_name'"
        _append_found "$vuln_name" "$points"
    else
        echo "Unsolved Vuln"
        _append_unsolved
    fi
}

# keep this line at the beginning, input your image metadata here 
# accepts two args: image name, and injects bool (true/false)
_header "Brainrot 2.0" "false"

check_text_exists "/home/rizzler/Forensics1.txt" "Skibidi, Skibidi Hawk Tuah Hawk" "Forensics 1 correct" "2"
check_text_exists "/home/rizzler/Forensics2.txt" "https://tophermitchell.hair" "Forensics 2 correct" "2"
check_text_exists "/home/rizzler/Forensics3.txt" "LowTaperFade" "Forensics 3 correct" "2"
check_text_not_exists "/etc/group" "chillguy:x:1003:" "User chillguy removed" "2"
check_text_not_exists "/etc/group" "koco:x:1006:" "User koco removed" "2"
check_text_exists "/etc/group" "Prison:x:1016:diddy" "Diddy added to Prison" "2"
check_text_not_exists "/etc/group" "grinch:x:1112:" "Hidden user Grinch removed" "2"
check_text_not_exists "/etc/group" "sys:x:3:grimace" "User grimace removed from sys group" "2"
check_file_deleted "/home/grimace/Fein.mp3" "Prohibited mp3 file removed" "2"
check_file_deleted "/home/rizzler/Music/ThickofIt.mp3" "Prohibited mp3 file removed" "2"
check_file_deleted "/home/rizzler/Pictures/chillguy.jpg" "Chill Guy image removed" "2"
check_file_deleted "/root/.nothing_here" "Malicious File Removed" "2"
check_file_deleted "/root/.secret" "Malicious File Removed" "2"
check_text_not_exists "/etc/profile" "ALIAS=" "Annoying alias script removed" "2"
check_text_exists "/etc/ufw/ufw.conf" "ENABLED=yes" "Firewall running" "2"
check_text_not_exists "/etc/sudoers" "NOPASSWD" "Removed insecure sudoers rule" "2"
check_file_deleted "/etc/sudoers.d/balsamicvinegar" "unnecessary sudeors file removed" "2"
check_text_exists "/etc/vsftpd.conf" "anon_mkdir_write_enable=NO" "anonymous FTP user is unable to create new directories" "2"
check_text_exists "/etc/vsftpd.conf" "ssl_enable=YES" "FTP SSL enabled" "2"
check_text_exists "/etc/vsftpd.conf" "ssl_tlsv1=YES" "SSL uses secure TLS" "2"
check_text_exists2 "/etc/vsftpd.conf" "force_local_logins_ssl=YES" "force_local_data_ssl=YES" "FTP forces SSL" "2"
check_text_exists3 "/etc/vsftpd.conf" "pasv_min_port=50000" "pasv_max_port=50200" "pasv_enable=YES" "FTP passive port range set" "2"
check_text_not_exists "/etc/ftpusers" "chillguy" "Chill Guy is not an ftpuser" "2"
check_text_exists "/etc/squid/squid.conf" "http_port 3128" "squid http port set to 3128" "2"
check_text_exists "/etc/squid/squid.conf" "http_access allow localhost" "squid allows localhost" "2"
check_text_exists "/etc/squid/squid.conf" "http_access deny CONNECT !SSL_ports" "squid only allows connection from secure SSL ports" "2"
check_file_permissions "/etc/shadow" "600" "Permissions on shadow file fixed" "2"
check_text_exists "/etc/login.defs" "ENCRYPT_METHOD SHA512" "SHA512 encryption enabled" "2"
check_text_exists2 "/etc/apt/apt.conf.d/20auto-upgrades" 'APT::Periodic::Update-Package-Lists "1";' 'APT::Periodic::Unattended-Upgrade "1"' "System set to automatically update" "2"
check_text_exists "/etc/sysctl.conf" "net.ipv4.conf.default.log_martians = 1" "Sysctl logs martians" "2"
check_packages "4g8" "4g8 removed" "2"
check_packages "wireshark" "Wireshark removed" "2"
check_packages2 "samba" "apache2" "Unauthorized services apache2 and samba removed" "2"
check_packages2 "ophcrack" "aircrack-ng" "Password cracking software removed" "2"
check_packages3 "qbittorrent" "transmission" "deluge" "Torrenting software removed" "2"
check_text_not_exists "/root/.bashrc" "alias nano=" "malicious alias removed" "2"
check_text_exists "/etc/audit/auditd.conf" "write_logs = yes" "auditd writes logs" "2"
check_text_exists "/etc/audit/auditd.conf" "max_restarts = 10" "auditd has 10 max restarts" "2"
check_text_exists "/etc/default/grub" 'GRUB_DISABLE_RECOVERY="true"' "GRUB recovery disabled" "2"
check_text_exists2 "/etc/grub.d/40_custom" "set check_signatures=enforce" "export check_signatures" "Grub check signatures enabled" "2"

# keep this line at the end, input the path to score report html here
# accepts two args: path to template html file, and path to actual html file
_terminate "/etc/scoring/report-template.html" "/home/rizzler/report.html"
