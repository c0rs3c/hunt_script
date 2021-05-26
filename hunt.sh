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

mkdir Configs



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



enum_subdomains() {
    echo -e "\n${Red}**************************************Subdomain Enumeration for Probable Subdomains Started**********************************${NC}"
    echo -e "${Red}Starting RECON ${NC}"
    echo -e "${Green}Using ASSETFINDER${NC}"
    assetfinder --subs-only $domain | tee assetfinder.txt
    echo -e "${Green}Using AMASS${NC}"
    amass enum -d $domain --passive -o amass.txt
    echo -e "${Green}Using FINDDOMAIN${NC}"
    findomain --target $domain --threads 50 -u findomains.txt
    echo -e "${Green}Using SUBFINDER${NC}"
    subfinder -d $domain -t 100 -o subfinder.txt
    if [ -f ~/.config/github/github-tokens.txt ];then
        echo -e "${Green}Using GITHUB-SUBDOMAINS${NC}"
        github-subdomains -t ~/.config/github/github-tokens.txt -d $domain -o git-subdomains.txt
    else
        echo -e "${Red}Github Token Not Set at ~/.config/github/github-tokens.txt : Hence skipping github subdomain enumeration${NC}"
    fi
    echo -e "${Green}Using CRTSH${NC}"
    curl -s https://crt.sh/\?q\=\%.$domain\&output\=json | jq -r '.[].name_value' | sed 's/\*\.//g' | tee crtsh.txt
    echo -e "${Green}Combining all subdomains from tools ${NC}"
    if [ -f probable-subdomains.txt.tmp ];then rm probable-subdomains.txt.tmp;fi
    if [ -f probable-subdomains.txt ];then rm probable-subdomains.txt;fi
    if [ -f assetfinder.txt ];then count=$(wc -l assetfinder.txt | cut -d " " -f1);printf "${Yellow}Assetfinder Domains: %s\n${NC}" $count;cat assetfinder.txt >> probable-subdomains.txt.tmp;rm assetfinder.txt;fi
    if [ -f amass.txt ];then count=$(wc -l amass.txt | cut -d " " -f1);printf "${Yellow}Amass Domains: %s\n${NC}" $count;cat amass.txt >> probable-subdomains.txt.tmp;rm amass.txt;fi
    if [ -f findomains.txt ];then count=$(wc -l findomains.txt | cut -d " " -f1);printf "${Yellow}Findomains Domains: %s\n${NC}" $count;cat findomains.txt >> probable-subdomains.txt.tmp;rm findomains.txt;fi
    if [ -f subfinder.txt ];then count=$(wc -l subfinder.txt | cut -d " " -f1);printf "${Yellow}Subfinder Domains: %s\n${NC}" $count;cat subfinder.txt >> probable-subdomains.txt.tmp;rm subfinder.txt;fi
    if [ -f crtsh.txt ];then count=$(wc -l crtsh.txt | cut -d " " -f1);printf "${Yellow}crtsh Domains: %s\n${NC}" $count;cat crtsh.txt >> probable-subdomains.txt.tmp;rm crtsh.txt;fi
    if [ -f git-subdomains.txt ];then count=$(wc -l git-subdomains.txt | cut -d " " -f1);printf "${Yellow}Git-subdomains Domains: %s\n${NC}" $count;cat git-subdomains.txt >> probable-subdomains.txt.tmp;rm git-subdomains.txt;fi
    cat probable-subdomains.txt.tmp | sort -u > probable-subdomains.txt;rm probable-subdomains.txt.tmp
    # echo -e "\n${Red}*****************************Setting Cron for Subdomain*******************************************${NC}"
    #Copying Probable Subdomains to another file for subdomain-slack notification
    # mkdir Slack-subdomain-notifier
    # cp probable-subdomains.txt Slack-subdomain-notifier/base-subdomains.txt
    # set_up_slack_notifier_cron
    #############################################################################
    if [ ! -f commonspeak2.txt ];then
        wget https://raw.githubusercontent.com/assetnote/commonspeak2-wordlists/master/subdomains/subdomains.txt -O commonspeak2.txt
        sed -i '/^$/d' commonspeak2.txt
    fi
    sed -i "s/$/\.$domain/" commonspeak2.txt #prepending subdomain name to given domain
    cs_count=$(wc -l commonspeak2.txt | cut -d " " -f1);printf "${Yellow}commonspeak2 Words: %s\n${NC}" $cs_count
    cat commonspeak2.txt >> probable-subdomains.txt
    psd_count=$(wc -l probable-subdomains.txt | cut -d " " -f1)
    printf "${Green}Generated all Domains with CommonSpeak Appended in SUBDOMAINS.TXT: %s\n${NC}" $psd_count
    if [ -f commonspeak2.txt ];then rm commonspeak2.txt;fi
    echo -e "\n${Green}**************************************Subdomain Enumeration for Probable Subdomains Finished**********************************${NC}"
}


resolve_subdomains(){
    if [ -f live-subdomains.txt ];then rm live-subdomains.txt;fi
    if [ -f live-subdomains.txt.tmp ];then rm live-subdomains.txt.tmp;fi
    if [ -f live-subdomains.txt.tmp.1 ];then rm live-subdomains.txt.tmp.1;fi
    echo -e "\n${Yellow}**************************************Resolving Probable Subdomains Started**********************************${NC}"
    if [[ -f "./Configs/resolvers.txt" ]]
    then
        echo "Resolver exists"
    else
        timeout 20 dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 20 -o Configs/resolvers.txt
    fi
    #Reliable resolvers from google , cloudflare, cisco and quad9
    echo -e "8.8.8.8\n1.1.1.1\n8.8.4.4\n1.0.0.1\n208.67.222.222\n9.9.9.9" > Configs/reliable-resolvers.txt
    echo -e "8.8.8.8\n1.1.1.1\n8.8.4.4\n1.0.0.1\n208.67.222.222\n9.9.9.9" >> Configs/resolvers.txt
    # echo $resolvers
    # shuffledns -d $domain -list probable-subdomains.txt -r Configs/resolvers.txt -t 15000 -o live-subdomains.txt
    massdns -r Configs/resolvers.txt -o S -w live-subdomains.txt.tmp  probable-subdomains.txt
    cat live-subdomains.txt.tmp | cut -d " " -f1 | sed "s/\.$//" | sort -u | tee live-subdomains.txt.tmp.1
    massdns -r Configs/reliable-resolvers.txt -o S -w live-subdomains.txt live-subdomains.txt.tmp.1
    rm live-subdomains.txt.tmp live-subdomains.txt.tmp.1
    # cat live-subdomains.txt
    echo -e "\n${Green}**************************************Resolving Probable Subdomains Finished**********************************${NC}"
}

brute_alt_subdomains(){
    echo -e "\n${Yellow}**************************************Alterd Domain Bruteforcing and Resolving Started**********************************${NC}"
    if [ -f altered-live-subdomains.txt ];then rm altered-live-subdomains.txt;fi
    if [ -f alt-dns-words.txt ]
    then
        echo "Alt Word List exists"
    else
        wget https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt -O alt-dns-words.txt
    fi
    echo -e "${Yellow}Generating Permutation of altered domains${NC}"
    altdns -i live-subdomains.txt -o altered-dns-output.txt -w alt-dns-words.txt
    alt_count=$(wc -l altered-dns-output.txt | cut -d " " -f1)
    printf "${Yellow} Total altered domains generated : %s\n${NC}" $alt_count
    echo -e "${Yellow} Resolving Altered Domains${NC}"
    # shuffledns -d $domain -list altered-dns-output.txt -r Configs/resolvers.txt -t 15000 -o altered-live-subdomains.txt
    massdns -r Configs/resolvers.txt -o S -w altered-live-subdomains.txt.tmp -t A altered-dns-output.txt
    cat altered-live-subdomains.txt.tmp | cut -d " " -f1 | sed "s/\.$//" | sort -u | tee altered-live-subdomains.txt.tmp.1
    massdns -r Configs/reliable-resolvers.txt -o S -w altered-live-subdomains.txt -t A altered-live-subdomains.txt.tmp.1
    if [ -f altered-live-subdomains.txt.tmp.1 ];then rm altered-live-subdomains.txt.tmp.1;fi
    if [ -f altered-live-subdomains.txt.tmp ];then rm altered-live-subdomains.txt.tmp;fi
    if [ -f altered-dns-output.txt ];then rm altered-dns-output.txt;fi
    if [ -f alt-dns-words.txt ];then rm alt-dns-words.txt;fi
    alt_live_count=$(wc -l altered-live-subdomains.txt | cut -d " " -f1)
    printf "${Yellow} Total altered live domains Found : %s\n${NC}" $alt_live_count
    echo -e "\n${Green}**************************************Altered Domain Bruteforcing and Resolving Finished**********************************${NC}"
}

get_CNAME(){
    cat subdomains.txt | dnsprobe -r CNAME -o subdomains-cname.txt
}

clean-ips(){
cat >> Port-Scan/clean-ips.py << EOL
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
touch Port-Scan/origin-ips.txt
python3 Port-Scan/clean-ips.py Port-Scan/all-ips.txt Port-Scan/origin-ips.txt
rm Port-Scan/clean-ips.py
}
do_port_scan(){
    echo -e "\n${Red}**************************************All Port and Services Scan Started**********************************${NC}"
    mkdir Port-Scan
    cat subdomains-with-ip.txt | cut -d " " -f3 | grep -E "([0-9]{0,3}\.){3}[0-9]{1,3}" | sort -u | tee Port-Scan/all-ips.txt
    # Call function to clean IPs by removing cloudflare IPs in it
    clean-ips
    while read ip; do
          echo -e "\n\n${Green}$ip${NC}"
          mkdir Port-Scan/$ip
          masscan $ip -p1-65535 --rate 10000 --wait 20 | tee tmp; grep -Po "(?<=port).*(?=\/)" tmp | sed 's/^ //' | tr '\n' ',' | sed -e 's/,$/\n/' |             xargs -n1 -I {} nmap -Pn -p{} -vvv -oN Port-Scan/$ip/services.txt $ip
          rm tmp
          echo -e "\n----------------------------------------------------------------------\n" >> Port-Scan/$ip/services.txt
          # For appending domain names in the service.txt file obtained by nmap
          grep $ip subdomains-with-ip.txt >> Port-Scan/$ip/services.txt
    done < Port-Scan/origin-ips.txt
    # For checking response when direct IP is accessed
    cat Port-Scan/origin-ips.txt | httpx -follow-redirects -status-code -title -web-server -cdn -silent -no-fallback -o Port-Scan/direct-ip-access.txt
    echo -e "\n${Red}**************************************All Port and Services Scanned**********************************${NC}"
}
do_dir_bruteforcing(){
    echo -e "\n${Red}**************************************Directory Brute Forcing Started*********************************${NC}"
    mkdir Directories
    mkdir Dir-Bf
    wget https://raw.githubusercontent.com/dark-warlord14/ffufplus/master/wordlist/dicc.txt
    xargs -P10 -I {} sh -c 'url="{}"; ffuf -r -c -H "Accept: */*" -H "X-Forwarded-For: 127.0.0.1" -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0" -u "{}/FUZZ" -w dicc.txt -t 80 -D -e js,php,bak,txt,asp,aspx,jsp,html,zip,jar,sql,json,old,gz,shtml,log,swp,yaml,yml,config,save,rsa,ppk -ac -se -o Directories/${url##*/}-${url%%:*}.json' < webdomains.txt
    #Extract data in nice format from json files given by ffuff
    cat Directories/* | jq '[.results[]|{status: .status, length: .length, url: .url}]' | grep -Po "status\":\s(\d{3})|length\":\s(\d{1,7})|url\":\s\"(http[s]?:\/\/.*?)\"" | paste -d' ' - - - | awk '{print $2" "$4" "$6}' | sed 's/\"//g' > Dir-Bf/directories-bf.txt
    mv dicc.txt Dir-Bf/
    rm -rf Directories/
    echo -e "\n${Red}**************************************Directory Brute Forcing Completed*********************************${NC}"
}

take_screenshots(){
    echo -e "\n${Red}**************************************Starting Screenshotting**************************************************${NC}"
    mkdir Screenshots
    cat webdomains.txt | aquatone -out Screenshots
    echo -e "\n${Red}**************************************Finished Screenshotting**************************************************${NC}"
}
do_nuclei_scan(){
    echo -e "\n${Red}**************************************Starting Nuclei Scans****************************************************${NC}"
    mkdir Nuclei-scans
    cat webdomains.txt | nuclei -c 200 -silent -t ~/nuclei-templates/ -o Nuclei-scans/nuclei-results.txt
    echo -e "\n${Red}**************************************Finished Nuclei Scans****************************************************${NC}"
}
extract_wayback_gau_urls(){
    echo -e "\n${Red}**************************************Extracting Wayback and Gau URLS******************************************${NC}"
	mkdir Archive
    waybackurls $domain | tee -a Archive/wb-gau-urls.tmp;gau $domain | tee -a Archive/wb-gau-urls.tmp;cat Archive/wb-gau-urls.tmp | sort -u > Archive/wb-gau-urls.txt;
    rm Archive/wb-gau-urls.tmp
	cat Archive/wb-gau-urls.txt  | sort -u | grep -P "\w+\.js(\?|$)" | httpx -silent -status-code -mc 200 | awk '{print $1}' | sort -u > Archive/jsurls.txt
	# Fetch Endpoints
	echo -e "[$Green+$NC] Fetching Endpoints from gau JS files"
	if [[ ! -f "$HOME/tools/LinkFinder/linkfinder.py" ]];
	then
		git clone https://github.com/GerbenJavado/LinkFinder.git $HOME/tools/LinkFinder
		apt install -y jsbeautifier
	fi
	for js in `cat Archive/jsurls.txt`;
	do
		python3 $HOME/tools/LinkFinder/linkfinder.py -i $js -o cli | anew Archive/endpoints.txt;
	done
    echo -e "\n${Red}**************************************Finished Extracting Wayback and Gau URLS*********************************${NC}"
}
do_paramining(){
    echo -e "\n${Red}**************************************Starting Paramining******************************************************${NC}"
	cat Archive/wb-gau-urls.txt  | sort -u | unfurl --unique keys > Archive/paramlist.txt
    mkdir Paramined
    grep ? Archive/wb-gau-urls.txt > Paramined/urls-with-parameters
    # This is added to find out unique URLs among URLs which differ just in value of the parameter.
    cat Paramined/urls-with-parameters | unfurl -u format %d%p | xargs -n1 -I {} erep -m1 {} Paramined/urls-with-parameters | tee Paramined/unique-urls-with-parameters.tmp | grep -vE 'jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|eot|js' | tee Paramined/unique-urls-with-parameters
    cd ~/tools/Arjun/
    python3 arjun.py --urls $working_dir/Paramined/unique-urls-with-parameters -t 50 -o $working_dir/Paramined/arjun-output.txt
    rm $working_dir/Paramined/unique-urls-with-parameters.tmp
    cd $working_dir
    echo -e "\n${Red}**************************************Finished Paramining******************************************************${NC}"

}

extract_using_gf(){
    mkdir Gf-extracted
    gf xss Archive/wb-gau-urls.txt | cut -d : -f3- | sort -u > Gf-extracted/$domain"_xss"
    gf ssti Archive/wb-gau-urls.txt | sort -u > Gf-extracted/$domain"_ssti"
    gf ssrf Archive/wb-gau-urls.txt | sort -u > Gf-extracted/$domain"_ssrf"
    gf sqli Archive/wb-gau-urls.txt | sort -u > Gf-extracted/$domain"_sqli"
    gf redirect  Archive/wb-gau-urls.txt  | cut -d : -f2- | sort -u > Gf-extracted/$domain"_redirect"
    gf rce  Archive/wb-gau-urls.txt | sort -u > Gf-extracted/$domain"_rce"
    gf potential Archive/wb-gau-urls.txt | cut -d : -f3- | sort -u > Gf-extracted/$domain"_potential"
    gf lfi  Archive/wb-gau-urls.txt | sort -u > Gf-extracted/$domain"_lfi"
}
fetch_subdomains_and_find_secrets_through_meg(){
    echo -e "\n${Red}**************************************Using Meg to fetch from Subdomains******************************************************${NC}"
	if [[ ! -d "$HOME/tools/gf-secrets" ]]
	then
		git clone https://github.com/dwisiswant0/gf-secrets $HOME/tools/gf-secrets
		cp "$HOME"/tools/gf-secrets/.gf/*.json ~/.gf
	fi
	meg -d 1000 -v / webdomains.txt
	mv out meg
	for i in `gf -list`; do [[ ${i} =~ "_secrets"* ]] && gf ${i} >> Gf-extracted/"${i}".txt; done
    echo -e "\n${Red}**************************************Finished using Meg to fetch from Subdomains******************************************************${NC}"
}

do_spidering(){
    echo -e "\n${Red}**************************************Starting GoSpider******************************************************${NC}"
    gospider -S webdomains.txt -o Gospider -c 10 -t 5 -d 5 --other-source
    cat Gospider/* > Gospider/all-gospider.txt
    echo -e "\n${Red}**************************************Finished GoSpider******************************************************${NC}"
}
hunt_for_xss(){
    echo -e "\n${Red}**************************************Starting XSS Hunting******************************************************${NC}"
    cat all-gospider.txt |  grep -e "code-200" |  awk '{print $5}'| grep "=" | qsreplace -a | grep -f in-scope-regex
    echo -e "\n${Red}**************************************Finished XSS Hunting******************************************************${NC}"
}
# while getopts ":d:D:r" opt; do
single_domain(){
    echo "Single Domain Called"
    # generate_github_dorks
    # enum_subdomains
    resolve_subdomains
    brute_alt_subdomains
    cat altered-live-subdomains.txt | anew live-subdomains.txt | tee permuted-live-subdomains
    mv live-subdomains.txt subdomains-with-ip.txt
    cat subdomains-with-ip.txt | cut -d " " -f1 | sed "s/\.$//" | tee subdomains.txt
    rm altered-live-subdomains.txt
    # rm probable-subdomains.txt Configs/reliable-resolvers.txt
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
multiple_domain(){
    echo "Multiple Domain Called"
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

