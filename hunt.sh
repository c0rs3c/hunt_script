#!/bin/bash
NC='\033[0m' # No Color
# Regular Colors
Black='\033[0;30m'        # Black
Red='\033[0;31m'          # Red
Green='\033[0;32m'        # Green
Yellow='\033[0;33m'       # Yellow
Blue='\033[0;34m'         # Blue
Purple='\033[0;35m'       # Purple
Cyan='\033[0;36m'         # Cyan
White='\033[0;37m'        # White

# Bold
BBlack='\033[1;30m'       # Black
BRed='\033[1;31m'         # Red
BGreen='\033[1;32m'       # Green
BYellow='\033[1;33m'      # Yellow
BBlue='\033[1;34m'        # Blue
BPurple='\033[1;35m'      # Purple
BCyan='\033[1;36m'        # Cyan
BWhite='\033[1;37m'       # White

# Underline
UBlack='\033[4;30m'       # Black
URed='\033[4;31m'         # Red
UGreen='\033[4;32m'       # Green
UYellow='\033[4;33m'      # Yellow
UBlue='\033[4;34m'        # Blue
UPurple='\033[4;35m'      # Purple
UCyan='\033[4;36m'        # Cyan
UWhite='\033[4;37m'       # White

# Background
On_Black='\033[40m'       # Black
On_Red='\033[41m'         # Red
On_Green='\033[42m'       # Green
On_Yellow='\033[43m'      # Yellow
On_Blue='\033[44m'        # Blue
On_Purple='\033[45m'      # Purple
On_Cyan='\033[46m'        # Cyan
On_White='\033[47m'       # White

# High Intensity
IBlack='\033[0;90m'       # Black
IRed='\033[0;91m'         # Red
IGreen='\033[0;92m'       # Green
IYellow='\033[0;93m'      # Yellow
IBlue='\033[0;94m'        # Blue
IPurple='\033[0;95m'      # Purple
ICyan='\033[0;96m'        # Cyan
IWhite='\033[0;97m'       # White

# Bold High Intensity
BIBlack='\033[1;90m'      # Black
BIRed='\033[1;91m'        # Red
BIGreen='\033[1;92m'      # Green
BIYellow='\033[1;93m'     # Yellow
BIBlue='\033[1;94m'       # Blue
BIPurple='\033[1;95m'     # Purple
BICyan='\033[1;96m'       # Cyan
BIWhite='\033[1;97m'      # White

# High Intensity backgrounds
On_IBlack='\033[0;100m'   # Black
On_IRed='\033[0;101m'     # Red
On_IGreen='\033[0;102m'   # Green
On_IYellow='\033[0;103m'  # Yellow
On_IBlue='\033[0;104m'    # Blue
On_IPurple='\033[0;105m'  # Purple
On_ICyan='\033[0;106m'    # Cyan
On_IWhite='\033[0;107m'   # White

# if [[ -z $1 ]]; then
# 	echo -e "[$Green+$NC] Usage: recon <domain.tld>"
# 	exit 1
# fi
# if [[ -z "$2" ]]; then
# 	echo -e "[$Red-$NC] If in-scope-regex not provided as second argument, XSS hunting shall not happen>"
# fi
# domain=$1
# working_dir=$(pwd)
# echo $working_dir

if [ ! -d $HOME/Hunt-script-tools ];then mkdir $HOME/Hunt-script-tools;fi

if [ ! -d Configs ];then mkdir Configs;fi
if [ ! -d Dir-subdomains ];then mkdir Dir-subdomains;fi
if [[ -f "./Configs/resolvers.txt" ]]
then
    printf "${Purple}[+] Resolver exists\n${NC}"
else
    timeout 30 dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 20 -o Configs/resolvers.txt
    echo -e "8.8.8.8\n1.1.1.1\n8.8.4.4\n1.0.0.1\n208.67.222.222\n9.9.9.9" > Configs/reliable-resolvers.txt
    # echo -e "\n8.8.8.8\n1.1.1.1\n8.8.4.4\n1.0.0.1\n208.67.222.222\n9.9.9.9"  >> Configs/resolvers.txt
    sed -i '/^$/d' Configs/resolvers.txt # Removing blank lines
fi
#Reliable resolvers from google , cloudflare, cisco and quad9




## Generate Crontab script for subdomain enumeration and then set crontab job
set_up_slack_notifier_cron(){
cat >> Slack-subdomain-notifier/$domain"-slack-sd-notifier.sh" << EOL
# For changing the current working directory to the directory of script. Since
#Crontab runs scripts with user's home directory as working directory
cd \$(dirname \$0)
source /root/.config/slack/slack-webhook-url.txt
echo \$SLACK_WEBHOOK_URL
new_subdomains=new-subdomain-\`date +"%d-%m-%y"\`.txt
assetfinder --subs-only $domain | tee assetfinder.txt
amass enum -d $domain --passive -o amass.txt
findomain --target $domain --threads 50 -u findomains.txt
subfinder -d $domain -t 100 -o subfinder.txt
github-subdomains -t ~/.config/github/github-tokens.txt -d $domain -o git-subdomains.txt
curl -s https://crt.sh/\?q\=\%.$domain\&output\=json | jq -r '.[].name_value' | sed 's/\*\.//g' | tee crtsh.txt
echo -e "\${Red}Combining all subdomains from tools \${NC}"
cat assetfinder.txt amass.txt findomains.txt subfinder.txt crtsh.txt git-subdomains.txt| sort -u  | tee probable-subdomains.txt
rm assetfinder.txt amass.txt findomains.txt subfinder.txt crtsh.txt git-subdomains.txt
cat probable-subdomains.txt | anew base-subdomains.txt > \$new_subdomains
rm probable-subdomains.txt
if [ -s \$new_subdomains ]
then
    echo "NEW SUBDOMAINS FOUND"
    cat \$new_subdomains | jq -Rs . | xargs -I %% curl -X POST -H 'Content-type: application/json' --data '{"text":"%%"}' \$SLACK_WEBHOOK_URL
else
    echo "REMOVING NEW SUBDOMAINS_FILE"
    rm \$new_subdomains
fi
EOL
chmod 777 Slack-subdomain-notifier/$domain"-slack-sd-notifier.sh"
echo "PATH=$PATH"
(crontab -l 2>/dev/null; echo "5 4 * * * $(pwd)/Slack-subdomain-notifier/$domain"-slack-sd-notifier.sh"") | crontab -
}


generate_github_dorks(){
    echo -e "${BIRed}USE GTHUB DORKER (alias gitdorker) to manually generate github dorks${NC}\n"
    echo -e "${BIGreen}python3 GitDorker.py -tf *tokenfile.txt* -d Dorks/alldorks.txt -q org:teslamotor -o git-output.txts${NC}\n"
    echo -e "${BIGreen}python3 GitDorker.py -tf *tokenfile.txt* -d Dorks/alldorks.txt -q tesla.com -o git-output.txts${NC}\n"
    sleep 10
}



enum_subdomains(){
    echo -e "\n${Cyan}[+] **************************************Subdomain Enumeration for Probable Subdomains Started**********************************${NC}"
    echo -e "${Cyan}[+] Starting RECON ${NC}"
    echo -e "${Green}[+] Using ASSETFINDER${NC}"
    assetfinder --subs-only $domain | tee Dir-subdomains/assetfinder.txt
    echo -e "${Green}[+] Using AMASS${NC}"
    amass enum -d $domain --passive -o Dir-subdomains/amass.txt -rf Configs/reliable-resolvers.txt
    echo -e "${Green}[+] Using FINDDOMAIN${NC}"
    findomain --target $domain --threads 50 -u Dir-subdomains/findomains.txt
    echo -e "${Green}[+] Using SUBFINDER${NC}"
    subfinder -d $domain -t 100 -o Dir-subdomains/subfinder.txt
    if [ -f ~/.config/github/github-tokens.txt ];then
        echo -e "${Green}[+] Using GITHUB-SUBDOMAINS${NC}"
        github-subdomains -t ~/.config/github/github-tokens.txt -d $domain -o Dir-subdomains/git-subdomains.txt
    else
        echo -e "${Red}[-] Github Token Not Set at ~/.config/github/github-tokens.txt : Hence skipping github subdomain enumeration${NC}"
    fi
    echo -e "${Green}[+] Using CRTSH${NC}"
    curl -s https://crt.sh/\?q\=\%.$domain\&output\=json | jq -r '.[].name_value' | sed 's/\*\.//g' | tee Dir-subdomains/crtsh.txt
    echo -e "${Yellow}[+] Combining all subdomains from tools ${NC}"
    # if [ -f Dir-subdomains/probable-subdomains.txt.tmp ];then rm Dir-subdomains/probable-subdomains.txt.tmp;fi
    # if [ -f Dir-subdomains/probable-subdomains.txt ];then rm Dir-subdomains/probable-subdomains.txt;fi
    # if [ -f Dir-subdomains/assetfinder.txt ];then count=$(wc -l Dir-subdomains/assetfinder.txt | cut -d " " -f1);printf "${Yellow}[+] Assetfinder Domains: %s\n${NC}" $count;cat Dir-subdomains/assetfinder.txt >> Dir-subdomains/probable-subdomains.txt.tmp;rm Dir-subdomains/assetfinder.txt;fi
    if [ -f Dir-subdomains/assetfinder.txt ];then count=$(wc -l Dir-subdomains/assetfinder.txt | cut -d " " -f1);printf "${Yellow}[+] Assetfinder Domains: %s\n${NC}" $count;cat Dir-subdomains/assetfinder.txt >> Dir-subdomains/probable-subdomains.txt.tmp;fi
    # if [ -f Dir-subdomains/amass.txt ];then count=$(wc -l Dir-subdomains/amass.txt | cut -d " " -f1);printf "${Yellow}[+] Amass Domains: %s\n${NC}" $count;cat Dir-subdomains/amass.txt >> Dir-subdomains/probable-subdomains.txt.tmp;rm Dir-subdomains/amass.txt;fi
    if [ -f Dir-subdomains/amass.txt ];then count=$(wc -l Dir-subdomains/amass.txt | cut -d " " -f1);printf "${Yellow}[+] Amass Domains: %s\n${NC}" $count;cat Dir-subdomains/amass.txt >> Dir-subdomains/probable-subdomains.txt.tmp;fi
    # if [ -f Dir-subdomains/findomains.txt ];then count=$(wc -l Dir-subdomains/findomains.txt | cut -d " " -f1);printf "${Yellow}[+] Findomains Domains: %s\n${NC}" $count;cat Dir-subdomains/findomains.txt >> Dir-subdomains/probable-subdomains.txt.tmp;rm Dir-subdomains/findomains.txt;fi
    if [ -f Dir-subdomains/findomains.txt ];then count=$(wc -l Dir-subdomains/findomains.txt | cut -d " " -f1);printf "${Yellow}[+] Findomains Domains: %s\n${NC}" $count;cat Dir-subdomains/findomains.txt >> Dir-subdomains/probable-subdomains.txt.tmp;fi
    # if [ -f Dir-subdomains/subfinder.txt ];then count=$(wc -l Dir-subdomains/subfinder.txt | cut -d " " -f1);printf "${Yellow}[+] Subfinder Domains: %s\n${NC}" $count;cat Dir-subdomains/subfinder.txt >> Dir-subdomains/probable-subdomains.txt.tmp;rm Dir-subdomains/subfinder.txt;fi
    if [ -f Dir-subdomains/subfinder.txt ];then count=$(wc -l Dir-subdomains/subfinder.txt | cut -d " " -f1);printf "${Yellow}[+] Subfinder Domains: %s\n${NC}" $count;cat Dir-subdomains/subfinder.txt >> Dir-subdomains/probable-subdomains.txt.tmp;fi
    # if [ -f Dir-subdomains/crtsh.txt ];then count=$(wc -l Dir-subdomains/crtsh.txt | cut -d " " -f1);printf "${Yellow}[+] Crtsh Domains: %s\n${NC}" $count;cat Dir-subdomains/crtsh.txt >> Dir-subdomains/probable-subdomains.txt.tmp;rm Dir-subdomains/crtsh.txt;fi
    if [ -f Dir-subdomains/crtsh.txt ];then count=$(wc -l Dir-subdomains/crtsh.txt | cut -d " " -f1);printf "${Yellow}[+] Crtsh Domains: %s\n${NC}" $count;cat Dir-subdomains/crtsh.txt >> Dir-subdomains/probable-subdomains.txt.tmp;fi
    # if [ -f Dir-subdomains/git-subdomains.txt ];then count=$(wc -l Dir-subdomains/git-subdomains.txt | cut -d " " -f1);printf "${Yellow}[+] Git-subdomains Domains: %s\n${NC}" $count;cat Dir-subdomains/git-subdomains.txt >> Dir-subdomains/probable-subdomains.txt.tmp;rm Dir-subdomains/git-subdomains.txt;fi
    if [ -f Dir-subdomains/git-subdomains.txt ];then count=$(wc -l Dir-subdomains/git-subdomains.txt | cut -d " " -f1);printf "${Yellow}[+] Git-subdomains Domains: %s\n${NC}" $count;cat Dir-subdomains/git-subdomains.txt >> Dir-subdomains/probable-subdomains.txt.tmp;fi
    cat Dir-subdomains/probable-subdomains.txt.tmp | sort -u > Dir-subdomains/probable-subdomains.txt;rm Dir-subdomains/probable-subdomains.txt.tmp
    # echo -e "\n${Cyan}*****************************Setting Cron for Subdomain*******************************************${NC}"
    #Copying Probable Subdomains to another file for subdomain-slack notification
    # mkdir Slack-subdomain-notifier
    # cp Dir-subdomains/probable-subdomains.txt Slack-subdomain-notifier/base-subdomains.txt
    # set_up_slack_notifier_cron
    #############################################################################
    if [ ! -f Dir-subdomains/commonspeak2.txt ];then
        wget https://raw.githubusercontent.com/assetnote/commonspeak2-wordlists/master/subdomains/subdomains.txt -O Dir-subdomains/commonspeak2.txt
        sed -i '/^$/d' Dir-subdomains/commonspeak2.txt
    fi
    sed -i "s/$/\.$domain/" Dir-subdomains/commonspeak2.txt #prepending subdomain name to given domain
    cs_count=$(wc -l Dir-subdomains/commonspeak2.txt | cut -d " " -f1);printf "${Yellow}[+] Commonspeak2 Words: %s\n${NC}" $cs_count
    # cat Dir-subdomains/commonspeak2.txt >> Dir-subdomains/probable-subdomains.txt
    ### For testing wordlist size is being reduced
    cat Dir-subdomains/commonspeak2.txt | head -n 1000 >> Dir-subdomains/probable-subdomains.txt
    psd_count=$(wc -l Dir-subdomains/probable-subdomains.txt | cut -d " " -f1)
    printf "${Green}Generated all Domains with CommonSpeak Appended in SUBDOMAINS.TXT: %s\n${NC}" $psd_count
    # if [ -f Dir-subdomains/commonspeak2.txt ];then rm Dir-subdomains/commonspeak2.txt;fi
    echo -e "\n${Green}**************************************Subdomain Enumeration for Probable Subdomains Finished**********************************${NC}"
}


resolve_subdomains(){
    if [ -f Dir-subdomains/live-subdomains.txt ];then rm Dir-subdomains/live-subdomains.txt;fi
    if [ -f Dir-subdomains/live-subdomains.txt.tmp ];then rm Dir-subdomains/live-subdomains.txt.tmp;fi
    if [ -f Dir-subdomains/live-subdomains.txt.tmp.1 ];then rm Dir-subdomains/live-subdomains.txt.tmp.1;fi
    echo -e "\n${Yellow}[+] **************************************Resolving Probable Subdomains Started**********************************${NC}"
    # echo $resolvers


    # #-------------------For ShuffleDNS-------------------------------------------#
    # echo -e "\n${Yellow}[+] Resolving from probable subdomains using all resolvers${NC}"
    # shuffledns -d $domain -list Dir-subdomains/probable-subdomains.txt -r Configs/resolvers.txt -t 15000 -o Dir-subdomains/live-subdomains.txt.tmp -v -t 20000
    # # massdns -q -r Configs/resolvers.txt -o S -w Dir-subdomains/live-subdomains.txt.tmp  Dir-subdomains/probable-subdomains.txt
    # # cat Dir-subdomains/live-subdomains.txt.tmp | cut -d " " -f1 | sed "s/\.$//" | sort -u | tee Dir-subdomains/live-subdomains.txt.tmp.1
    # echo -e "\n${Yellow}[+] Resolving from probable subdomains using ---RELIABLE--- resolvers${NC}"
    # shuffledns -d $domain -list Dir-subdomains/live-subdomains.txt.tmp -r Configs/reliable-resolvers.txt -t 15000 -o Dir-subdomains/live-subdomains.txt -v -t 20000
    # # massdns -q -r Configs/reliable-resolvers.txt -o S -w Dir-subdomains/live-subdomains.txt Dir-subdomains/live-subdomains.txt.tmp.1
    # rm Dir-subdomains/live-subdomains.txt.tmp
    # #-------------------For ShuffleDNS-------------------------------------------#

    #-------------------For MassDNS-------------------------------------------#
    echo -e "\n${Yellow}[+] Resolving from probable subdomains using all resolvers${NC}"
    # shuffledns -d $domain -list Dir-subdomains/probable-subdomains.txt -r Configs/resolvers.txt -t 15000 -o Dir-subdomains/live-subdomains.txt.tmp -v -t 40000
    massdns -q -r Configs/resolvers.txt -o S -w Dir-subdomains/live-subdomains.txt.tmp  Dir-subdomains/probable-subdomains.txt -s 20000
    cat Dir-subdomains/live-subdomains.txt.tmp | cut -d " " -f1 | sed "s/\.$//" | sort -u > Dir-subdomains/live-subdomains.txt.tmp.1
    echo -e "\n${Yellow}[+] Resolving from probable subdomains using ---RELIABLE--- resolvers${NC}"
    # shuffledns -d $domain -list Dir-subdomains/live-subdomains.txt.tmp -r Configs/reliable-resolvers.txt -t 15000 -o Dir-subdomains/live-subdomains.txt -v -t 40000
    massdns -q -r Configs/reliable-resolvers.txt -o S -w Dir-subdomains/live-subdomains.txt Dir-subdomains/live-subdomains.txt.tmp.1 -s 20000
    rm Dir-subdomains/live-subdomains.txt.tmp Dir-subdomains/live-subdomains.txt.tmp.1
    #-------------------For MassDNS-------------------------------------------#
    count=$(cat Dir-subdomains/live-subdomains.txt | cut -d " " -f1 | sort -u | wc -l | cut -d " " -f1)
    printf "${Yellow}[+] Live subdomains found before Alt-Bruteforcing: %s\n${NC}" $count

    echo -e "\n${Green}[+] **************************************Resolving Probable Subdomains Finished**********************************${NC}"
}

brute_alt_subdomains(){
    echo -e "\n${Yellow}[+] **************************************Alterd Domain Bruteforcing and Resolving Started**********************************${NC}"
    if [ -f Dir-subdomains/altered-live-subdomains.txt ];then rm Dir-subdomains/altered-live-subdomains.txt;fi
    if [ -f Dir-subdomains/alt-dns-words.txt ]
    then
        printf "${Purple}[+] Alt Word List exists\n${NC}"
    else
        wget https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt -O Dir-subdomains/alt-dns-words.txt
    fi
    echo -e "${Yellow}[+] Generating Permutation of altered domains${NC}"
    cat Dir-subdomains/live-subdomains.txt | cut -d " " -f1 | sed "s/\.$//" | sort -u > Dir-subdomains/live-subdomains.txt.tmp # Done because live subdomains has fields after subdomains found
    # For Testing : No. of alt domain words is being reduced
    altdns -i Dir-subdomains/live-subdomains.txt.tmp -o Dir-subdomains/altered-dns-output.txt.1 -w Dir-subdomains/alt-dns-words.txt
    cat Dir-subdomains/altered-dns-output.txt.1 | head -n 800 > Dir-subdomains/altered-dns-output.txt
    # altdns -i Dir-subdomains/live-subdomains.txt.tmp -o Dir-subdomains/altered-dns-output.txt -w Dir-subdomains/alt-dns-words.txt
    # rm Dir-subdomains/live-subdomains.txt.tmp

    alt_count=$(wc -l Dir-subdomains/altered-dns-output.txt | cut -d " " -f1)
    printf "${Yellow}[+] Total altered domains generated : %s\n${NC}" $alt_count

    # #-------------------For ShuffleDNS-------------------------------------------#
    # echo -e "${Yellow}[+] Resolving Altered Domains with all Resolvers${NC}"
    # shuffledns -d $domain -list Dir-subdomains/altered-dns-output.txt -r Configs/resolvers.txt -t 15000 -o Dir-subdomains/altered-live-subdomains.txt.tmp -v -t 20000
    # # massdns -q -r Configs/resolvers.txt -o S -w Dir-subdomains/altered-live-subdomains.txt.tmp -t A Dir-subdomains/altered-dns-output.txt --processes 100
    # # cat Dir-subdomains/altered-live-subdomains.txt.tmp | cut -d " " -f1 | sed "s/\.$//" | sort -u > tee Dir-subdomains/altered-live-subdomains.txt.tmp.1
    # echo -e "$[+] {Yellow} Resolving Altered Domains with ---RELIABLE--- Resolvers${NC}"
    # shuffledns -d $domain -list Dir-subdomains/altered-live-subdomains.txt.tmp -r Configs/reliable-resolvers.txt -t 20000 -o Dir-subdomains/altered-live-subdomains.txt -v -t 20000
    # # massdns -q -r Configs/reliable-resolvers.txt -o S -w Dir-subdomains/altered-live-subdomains.txt -t A Dir-subdomains/altered-live-subdomains.txt.tmp
    # # if [ -f Dir-subdomains/altered-live-subdomains.txt.tmp.1 ];then rm Dir-subdomains/altered-live-subdomains.txt.tmp.1;fi
    # if [ -f Dir-subdomains/altered-live-subdomains.txt.tmp ];then rm Dir-subdomains/altered-live-subdomains.txt.tmp;fi
    # if [ -f Dir-subdomains/altered-dns-output.txt ];then rm Dir-subdomains/altered-dns-output.txt;fi
    # if [ -f Dir-subdomains/alt-dns-words.txt ];then rm Dir-subdomains/alt-dns-words.txt;fi
    # #-------------------For ShuffleDNS-------------------------------------------#

    #-------------------For MassDNS-------------------------------------------#
    echo -e "${Yellow}[+] Resolving Altered Domains with all Resolvers${NC}"
    # shuffledns -d $domain -list Dir-subdomains/altered-dns-output.txt -r Configs/resolvers.txt -t 15000 -o Dir-subdomains/altered-live-subdomains.txt.tmp -v -t 40000
    massdns -q -r Configs/resolvers.txt -o S -w Dir-subdomains/altered-live-subdomains.txt.tmp -t A Dir-subdomains/altered-dns-output.txt -s 20000
    cat Dir-subdomains/altered-live-subdomains.txt.tmp | cut -d " " -f1 | sed "s/\.$//" | sort -u > Dir-subdomains/altered-live-subdomains.txt.tmp.1
    echo -e "${Yellow}[+]Resolving Altered Domains with ---RELIABLE--- Resolvers${NC}"
    # shuffledns -d $domain -list Dir-subdomains/altered-live-subdomains.txt.tmp -r Configs/reliable-resolvers.txt -t 15000 -o Dir-subdomains/altered-live-subdomains.txt -v -t 40000
    massdns -q -r Configs/reliable-resolvers.txt -o S -w Dir-subdomains/altered-live-subdomains.txt -t A Dir-subdomains/altered-live-subdomains.txt.tmp.1 -s 20000
    if [ -f Dir-subdomains/altered-live-subdomains.txt.tmp ];then rm Dir-subdomains/altered-live-subdomains.txt.tmp;fi
    if [ -f Dir-subdomains/altered-live-subdomains.txt.tmp.1 ];then rm Dir-subdomains/altered-live-subdomains.txt.tmp.1;fi
    if [ -f Dir-subdomains/altered-dns-output.txt ];then rm Dir-subdomains/altered-dns-output.txt;fi
    if [ -f Dir-subdomains/alt-dns-words.txt ];then rm Dir-subdomains/alt-dns-words.txt;fi
    #-------------------For MassDNS-------------------------------------------#

    alt_live_count=$(wc -l Dir-subdomains/altered-live-subdomains.txt | cut -d " " -f1)
    printf "${Yellow}[+] Total altered live domains Found : %s\n${NC}" $alt_live_count
    cat Dir-subdomains/altered-live-subdomains.txt
    echo -e "\n${Green}[+] **************************************Altered Domain Bruteforcing and Resolving Finished**********************************${NC}"
}

get_CNAME(){
    cat subdomains-with-ip.txt | grep CNAME
}

clean-ips(){
cat > Dir-port-scans/clean-ips.py << EOL
import sys
import requests
from ipaddress import ip_network, ip_address

def output_valid_ips(ips):
    ipvs4 = "https://www.cloudflare.com/ips-v4"
    ipvs6 = "https://www.cloudflare.com/ips-v6"

    ipranges = requests.get(ipvs4).text.split("\n")[:-1]  # removing last trailing space
    ipranges += requests.get(ipvs6).text.split("\n")[
        :-1
    ]  # removing last trailing space
    nets = []
    for iprange in ipranges:
        nets.append(ip_network(iprange))
    valid_ips = []
    for ip in ips:
        if ip == "":  # skip empty line
            continue
        valid = True
        for net in nets:
            if ip_address(ip) in net:
                valid = False
                break
        if valid:
            valid_ips.append(ip)
    return valid_ips


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(
            """
      Usage : python {} input_file_path output_file_path
      """.format(
                __file__
            )
        )
        sys.exit(1)
    file_name, output_file = sys.argv[1], sys.argv[2]

    with open(file_name) as f:
        ips = f.read().split("\n")
    valid_ips = output_valid_ips(ips)

    with open(output_file, "w") as f:
        for ip in valid_ips[:-1]:
            f.write(ip + "\n")
        # no new line after last line
        # f.write(valid_ips[-1])
EOL
touch Dir-port-scans/origin-ips.txt
python3 Dir-port-scans/clean-ips.py Dir-port-scans/all-ips.txt Dir-port-scans/origin-ips.txt
rm Dir-port-scans/clean-ips.py
}
do_port_scan(){
    echo -e "\n${Blue}[+] **************************************All Port and Services Scan Started**********************************${NC}"
    rm -rf Dir-port-scans
    mkdir Dir-port-scans
    cat Dir-subdomains/subdomains-with-ip.txt | cut -d " " -f3 | grep -E "([0-9]{0,3}\.){3}[0-9]{1,3}" | sort -u | tee Dir-port-scans/all-ips.txt
    # Call function to clean IPs by removing cloudflare IPs in it
    clean-ips
    while read ip; do
          printf "\n\n${Green}[+] Scanning: %s\n${NC}" $ip
          mkdir Dir-port-scans/$ip
          # sudo masscan $ip -p1-65535 --rate 100000 --wait 10 > Dir-port-scans/tmp
          sudo masscan $ip --top-ports 1000 --rate 100000 --wait 5 > Dir-port-scans/tmp
          if [ $(wc -l Dir-port-scans/tmp | cut -d " " -f1) -eq 0 ]
          then
            printf "${Red}[-] No opened ports found on %s\n${NC}" $ip
          else
            printf "${Yellow}[+] Opened ports on %s are:\n${NC}" $ip
            printf ${Yellow};cat Dir-port-scans/tmp;printf ${NC};
            cat Dir-port-scans/tmp >> Dir-port-scans/open-ports-all-ips
            grep -Po "(?<=port).*(?=\/)" Dir-port-scans/tmp | sed 's/^ //' | tr '\n' ',' | sed -e 's/,$/\n/' | xargs -I {} nmap -Pn -p{} -vvv -oN Dir-port-scans/$ip/services.txt $ip
            rm Dir-port-scans/tmp
          fi
          echo -e "\n----------------------------------------------------------------------\n" >> Dir-port-scans/$ip/services.txt
          # For appending domain names in the service.txt file obtained by nmap
          grep $ip Dir-subdomains/subdomains-with-ip.txt >> Dir-port-scans/$ip/services.txt
    done < Dir-port-scans/origin-ips.txt
    For checking response when direct IP is accessed
    #All ips being used instead of origin IPs, because let httpx also detect any CDN
    cat Dir-port-scans/all-ips.txt | httpx -follow-redirects -status-code -title -web-server -cdn -silent -no-fallback -tech-detect -o Dir-port-scans/direct-ip-access.txt
    echo -e "\n${Green}[+] **************************************All Port and Services Scanned**********************************${NC}"
}
do_dir_bruteforcing(){
    echo -e "\n${Blue}[+] **************************************Directory Brute Forcing Started*********************************${NC}"
    if [ -d Dir-bf ];then rm -rf Dir-bf;fi
    mkdir Dir-bf
    if [ ! -f Dir-bf/dicc.txt ];then
        wget https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dicc.txt -O Dir-bf/dicc.txt
    else
        printf "dicc exists"
    fi
    xargs -P10 -I {} sh -c 'url="{}"; ffuf -r -c -H "Accept: */*" -H "X-Forwarded-For: 127.0.0.1" -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0" -u "{}/FUZZ" -w Dir-bf/dicc.txt -t 80 -D -e js,php,bak,txt,asp,aspx,jsp,html,zip,jar,sql,json,old,gz,shtml,log,swp,yaml,yml,config,save,rsa,ppk -ac -se -o Dir-bf/${url##*/}-${url%%:*}.json' < Dir-subdomains/webdomains.txt
    #Extract data in nice format from json files given by ffuff
    cat Dir-bf/* | jq '[.results[]|{status: .status, length: .length, url: .url}]' | grep -Po "status\":\s(\d{3})|length\":\s(\d{1,7})|url\":\s\"(http[s]?:\/\/.*?)\"" | paste -d' ' - - - | sed 's/\"//g' > Dir-bf/all-subdomains-directories-bf.txt
    echo -e "\n${Red}[+] **************************************Directory Brute Forcing Completed*********************************${NC}"
}

take_screenshots(){
    echo -e "\n${Red}[+] **************************************Starting Screenshotting**************************************************${NC}"
    mkdir Screenshots
    cat webdomains.txt | aquatone -out Screenshots
    echo -e "\n${Red}[+] **************************************Finished Screenshotting**************************************************${NC}"
}
do_nuclei_scan(){
    echo -e "\n${Blue}[+] **************************************Starting Nuclei Scans****************************************************${NC}"
    if [ -d Dir-nuclei-scan ];then rm -rf Dir-nuclei-scan;fi
    mkdir Dir-nuclei-scan
    cat Dir-subdomains/webdomains.txt | nuclei -c 200 -silent -t ~/nuclei-templates/ -o Dir-nuclei-scan/nuclei-results.txt
    echo -e "\n${Red}[+] **************************************Finished Nuclei Scans****************************************************${NC}"
}
extract_wayback_gau_urls(){
    echo -e "\n${Blue}[+] **************************************Extracting Wayback and Gau URLS******************************************${NC}"
	if [ -d Dir-archive ];then rm -rf Dir-archive;fi
    mkdir Dir-archive
    printf "${Yellow}[+] Using waybackurl\n${NC}"
    waybackurls $domain | tee -a Dir-archive/wb-gau-urls.tmp;
    printf "${Yellow}[+] Using gau\n${NC}"
    gau $domain | tee -a Dir-archive/wb-gau-urls.tmp
    cat Dir-archive/wb-gau-urls.tmp | sort -u > Dir-archive/wb-gau-urls.txt
    rm Dir-archive/wb-gau-urls.tmp
    printf "${Yellow}[+] Extracting js files from archive\n${NC}"
	cat Dir-archive/wb-gau-urls.txt  | sort -u | grep -P "\w+\.js(\?|$)" | httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u > Dir-archive/jsurls.txt
	# Fetch Endpoints
	# echo -e "[$Green+$NC] Fetching Endpoints from gau JS files"
    printf "${Yellow}[+] Fetching Endpoints from archived JS files${NC}"
	if [[ ! -f "$HOME/Hunt-script-tools/LinkFinder/linkfinder.py" ]];
	then
		git clone https://github.com/GerbenJavado/LinkFinder.git $HOME/tools/LinkFinder
		apt install -y jsbeautifier
	fi
	for js in `cat Dir-archive/jsurls.txt`;
	do
		python3 $HOME/tools/LinkFinder/linkfinder.py -i $js -o cli | anew Dir-archive/js-extracted-endpoints.txt;
	done
    echo -e "\n${Green}[+] **************************************Finished Extracting Wayback and Gau URLS*********************************${NC}"
}
do_paramining(){
    echo -e "\n${Red}[+] **************************************Starting Paramining******************************************************${NC}"
	cat Dir-archive/wb-gau-urls.txt  | sort -u | unfurl --unique keys > Dir-archive/paramlist.txt
    mkdir Paramined
    grep ? Dir-archive/wb-gau-urls.txt > Paramined/urls-with-parameters
    # This is added to find out unique URLs among URLs which differ just in value of the parameter.
    cat Paramined/urls-with-parameters | unfurl -u format %d%p | xargs -n1 -I {} erep -m1 {} Paramined/urls-with-parameters | tee Paramined/unique-urls-with-parameters.tmp | grep -vE 'jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|eot|js' | tee Paramined/unique-urls-with-parameters
    cd ~/tools/Arjun/
    python3 arjun.py --urls $working_dir/Paramined/unique-urls-with-parameters -t 50 -o $working_dir/Paramined/arjun-output.txt
    rm $working_dir/Paramined/unique-urls-with-parameters.tmp
    cd $working_dir
    echo -e "\n${Red}[+] **************************************Finished Paramining******************************************************${NC}"

}

extract_using_gf(){
    mkdir Dir-gf-extracted
    gf xss Dir-archive/wb-gau-urls.txt | cut -d : -f3- | sort -u > Dir-gf-extracted/$domain"_xss"
    gf ssti Dir-archive/wb-gau-urls.txt | sort -u > Dir-gf-extracted/$domain"_ssti"
    gf ssrf Dir-archive/wb-gau-urls.txt | sort -u > Dir-gf-extracted/$domain"_ssrf"
    gf sqli Dir-archive/wb-gau-urls.txt | sort -u > Dir-gf-extracted/$domain"_sqli"
    gf redirect  Dir-archive/wb-gau-urls.txt  | cut -d : -f2- | sort -u > Dir-gf-extracted/$domain"_redirect"
    gf rce  Dir-archive/wb-gau-urls.txt | sort -u > Dir-gf-extracted/$domain"_rce"
    gf potential Dir-archive/wb-gau-urls.txt | cut -d : -f3- | sort -u > Dir-gf-extracted/$domain"_potential"
    gf lfi  Dir-archive/wb-gau-urls.txt | sort -u > Dir-gf-extracted/$domain"_lfi"
}
fetch_subdomains_and_find_secrets_through_meg(){
    echo -e "\n${Red}[+] **************************************Using Meg to fetch from Subdomains******************************************************${NC}"
	if [[ ! -d "$HOME/tools/gf-secrets" ]]
	then
		git clone https://github.com/dwisiswant0/gf-secrets $HOME/tools/gf-secrets
		cp "$HOME"/tools/gf-secrets/.gf/*.json ~/.gf
	fi
	meg -d 1000 -v / Dir-subdomains/webdomains.txt
	mv out meg
	for i in `gf -list`; do [[ ${i} =~ "_secrets"* ]] && gf ${i} >> Dir-gf-extracted/"${i}".txt; done
    echo -e "\n${Red}[+] **************************************Finished using Meg to fetch from Subdomains******************************************************${NC}"
}

do_spidering(){
    echo -e "\n${Red}[+] **************************************Starting GoSpider******************************************************${NC}"
    gospider -S Dir-subdomains/webdomains.txt -o Gospider -c 10 -t 5 -d 5 --other-source
    cat Gospider/* > Gospider/all-gospider.txt
    echo -e "\n${Red}[+] **************************************Finished GoSpider******************************************************${NC}"
}
hunt_for_xss(){
    echo -e "\n${Red}[+] **************************************Starting XSS Hunting******************************************************${NC}"
    cat all-gospider.txt |  grep -e "code-200" |  awk '{print $5}'| grep "=" | qsreplace -a | grep -f in-scope-regex
    echo -e "\n${Red}[+] **************************************Finished XSS Hunting******************************************************${NC}"
}
# while getopts ":d:D:r" opt; do
single_domain(){
    printf "${Purple}[+] Single Domain Called\n${NC}"
    # generate_github_dorks
    # enum_subdomains
    # resolve_subdomains
    # brute_alt_subdomains
    # printf "${Yellow}[+] Listing altered live domains not present in current found live domains\n${NC}"
    # cat Dir-subdomains/altered-live-subdomains.txt | anew Dir-subdomains/live-subdomains.txt | tee Dir-subdomains/permuted-live-subdomains.txt
    count=$(wc -l Dir-subdomains/permuted-live-subdomains.txt | cut -d " " -f1)
    printf "${Yellow}[+] No. of Total altered live domains not present in current found live domains: %s\n${NC}" $count
    # if [ -f Dir-subdomains/permuted-live-subdomains.txt ]; then rm Dir-subdomains/permuted-live-subdomains.txt;fi
    # echo -e "\n"
    # mv Dir-subdomains/live-subdomains.txt Dir-subdomains/subdomains-with-ip.txt
    # cat Dir-subdomains/subdomains-with-ip.txt | cut -d " " -f1 | sed "s/\.$//" | sort -u | tee Dir-subdomains/subdomains.txt
    # count=$(wc -l Dir-subdomains/subdomains.txt | cut -d " " -f1)
    # printf "${Yellow}[+] All subdomains found : %s\n${NC}" $count
    # rm Dir-subdomains/altered-live-subdomains.txt
    # rm Dir-subdomains/probable-subdomains.txt Configs/reliable-resolvers.txt
    # if [ -f Dir-subdomains/webdomains.txt];then rm Dir-subdomains/webdomains.txt;fi
    # # if [ -f Dir-subdomains/webdomains.txt.1];then rm Dir-subdomains/webdomains.txt.1;fi
    # printf "${Yellow}[+] Finding webdomains from all found subdomains\n${NC}"
    # printf ${Green}
    # cat Dir-subdomains/subdomains.txt | httprobe | tee Dir-subdomains/webdomains.txt.1
    # printf ${NC}
    # cat Dir-subdomains/webdomains.txt.1 | sort -u | tee Dir-subdomains/webdomains.txt
    # rm Dir-subdomains/webdomains.txt.1
    # fetch_subdomains_and_find_secrets_through_meg
    # get_CNAME
    # do_port_scan
    # do_dir_bruteforcing
    # do_nuclei_scan
    extract_wayback_gau_urls
    extract_using_gf
    # take_screenshots
    # do_spidering
    # if [[ -z $2 ]];then
    #     hunt_for_xss
    # fi
    # do_paramining
}
multiple_domain(){
    printf "${Purple}Multiple Domain Called\n{$NC}"
    echo $domain_file
    while read dom; do
        echo $dom
        # if [[ $dom =~ \* ]];then
        #     domain=$dom
        #     enum_subdomains
        #     resolve_subdomains
        #     brute_alt_subdomains
        #     cat altered-live-subdomains.txt | anew live-subdomains.txt | tee permuted-live-subdomains
        #     mv live-subdomains.txt subdomains-with-ip.txt
        #     cat subdomains-with-ip.txt | cut -d " " -f1 | sed "s/\.$//" | tee subdomains.txt
        #     rm altered-live-subdomains.txt  altered-dns-output.txt altered-live-subdomains.txt.tmp altered-live-subdomains.txt.tmp.1 live-subdomains.txt.tmp live-subdomains.txt.tmp.1 probable-subdomains.txt  #### A few more files like resolvers , alt-wordlist needs to be removed
        #     cat subdomains.txt | httprobe | sort -u | tee webdomains.txt
        #     else
        # fi

    done < $domain_file
        generate_github_dorks
        # enum_subdomains
        # resolve_subdomains
        # brute_alt_subdomains
        # cat altered-live-subdomains.txt | anew live-subdomains.txt | tee permuted-live-subdomains
        # mv live-subdomains.txt subdomains-with-ip.txt
        # cat subdomains-with-ip.txt | cut -d " " -f1 | sed "s/\.$//" | tee subdomains.txt
        # rm altered-live-subdomains.txt alt-dns-words.txt altered-dns-output.txt altered-live-subdomains.txt.tmp altered-live-subdomains.txt.tmp.1 live-subdomains.txt.tmp live-subdomains.txt.tmp.1 probable-subdomains.txt Configs/reliable-resolvers.txt
        # cat subdomains.txt | httprobe | sort -u | tee webdomains.txt
        # fetch_subdomains_and_find_secrets_through_meg
        # get_CNAME
        # do_port_scan
        # do_dir_bruteforcing
        # do_nuclei_scan
        # extract_wayback_gau_urls
        # extract_using_gf
        # take_screenshots
        # do_spidering
        # if [[ -z $2 ]];then
        #     hunt_for_xss
        # fi
        # do_paramining
}
while getopts ":d:D:r:" opt; do
# while getopts "d:D:r" opt; do
	case $opt in
        d ) domain=$OPTARG;
		    ;;
        D ) domain_file=$OPTARG;
		    ;;
		\? | h ) echo "Usage  :";
			 echo "         -d	Single Domain";
			 echo "         -D	Multiple Domain File";
			 # echo "         -r	In Scope Regex";
		         ;;
		: ) echo "Invalid Argument";
		     ;;
	esac
done
shift $((OPTIND -1))
if [[ -n $domain_file ]];then
    multiple_domain
else
    single_domain
fi
