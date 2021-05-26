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

echo "SHELL=/bin/bash" | crontab -
(crontab -l 2>/dev/null;echo "PATH=$PATH") | crontab -
mkdir -p /root/.config/slack
if [[ -f "/root/.config/slack/slack-webhook-url.txt" ]]
then 
    echo -e "$Green[+] Slack Webhook URL file exists $NC"
else    
    touch /root/.config/slack/slack-webhook-url.txt
    echo -e "$Green[+]Set webhook URL in /root/.config/slack/slack-webhook-url.txt $NC"
fi

mkdir -p /root/.config/github
if [[ -f "/root/.config/github/github-tokens.txt" ]]
then 
    echo -e "$Green[+] GitHub Token file exists $NC"
else    
    touch /root/.config/github/github-tokens.txt
    echo -e "$Green[+]Set Github token in /root/.config/github/github-tokens.txt $NC"

