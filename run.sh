#!/bin/bash
	
url=$1

#Checking if the script runs with root permissions.
if [ "$EUID" -ne 0 ]
      then echo -e "\n\n Script must be run as root permissions!! \n"
      exit
fi

#Checking if the tools are installed.
#Assetfinder
if [ ! -x "$(command -v assetfinder)" ]; then
	echo "[-] Assetfinder is not installed."
	read -p "Do you want to install assetfinder? [Y/N]: " choose
	if [ $choose -eq "Y" ]; then
		apt-get update && go get -u github.com/tomnomnom/assetfinder
	else
		echo "The script cannot continue, bye!"
		exit
	fi
fi

#Amass
if [ ! -x "$(command -v amass)" ]; then
	echo "[-] Amass is not installed."
	read -p "Do you want to install Amass? [Y/N]: " choose
	if [ $choose -eq "Y" ]; then
		apt-get update && go install -v github.com/OWASP/Amass/v3/...@master
	else
		echo "The script cannot continue, bye!"
		exit
	fi
fi	
#Httprobe
if [ ! -x "$(command -v httprobe)" ]; then
	echo "[-] Httprobe is not installed."
	read -p "Do you want to install Httprobe? [Y/N]: " choose
	if [ $choose -eq "Y" ]; then
		apt-get update && go get -u github.com/tomnomnom/httprobe
	else
		echo "The script cannot continue, bye!"
		exit
	fi
fi
#Eyewitness
if [ ! -x "$(command -v eyewitness)" ]; then
	echo "[-] EyeWitness is not installed."
	read -p "Do you want to install EyeWitness? [Y/N]: " choose
	if [ $choose -eq "Y" ]; then
		apt-get update && apt-get install eyewitness -y
	else
		echo "The script cannot continue, bye!"
		exit
	fi
fi


#Creating all necessary folders.
if [ ! -d "$url" ];then
	mkdir $url
fi
if [ ! -d "$url/recon" ];then
	mkdir $url/recon
fi
if [ ! -d "$url/recon/scans" ];then
	mkdir $url/recon/scans
fi
if [ ! -d "$url/recon/httprobe" ];then
	mkdir $url/recon/httprobe
fi
if [ ! -d "$url/recon/gowitness" ];then
	mkdir $url/recon/gowitness
fi
if [ ! -d "$url/recon/wayback" ];then
	mkdir $url/recon/wayback
fi
if [ ! -f "$url/recon/httprobe/subdomain_alive.txt" ];then
	touch $url/recon/httprobe/subdomain_alive.txt
fi
if [ ! -f "$url/recon/subdomains.txt" ];then
	touch $url/recon/subdomains.txt
fi
if [ ! -f "$url/recon/wayback/wayback_output.txt" ];then
	touch $url/recon/wayback/wayback_output.txt
fi

 
echo "[!] Checking for subdomains with assetfinder......"
assetfinder $url >> $url/recon/subdomains1.txt
cat $url/recon/subdomains1.txt | grep $1 >> $url/recon/subdomains.txt
rm $url/recon/subdomains1.txt
 
echo "[!] Checking for subdomains with Amass......"
amass enum -d $url >> $url/recon/subdomains1.txt
sort -u $url/recon/subdomains1.txt >> $url/recon/subdomains.txt
rm $url/recon/subdomains1.txt
 
echo "[!] Probing for alive domains......"
cat $url/recon/subdomains.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443' >> $url/recon/httprobe/a.txt
sort -u $url/recon/httprobe/a.txt > $url/recon/httprobe/alive_subdomains.txt
rm $url/recon/httprobe/a.txt
 
echo "[!] Scanning for open ports with Nmap......"
nmap -iL $url/recon/httprobe/alive_subdomains.txt -T4 -oA $url/recon/scans/nmap_scan.txt
 
echo "[!] Taking wayback data......"
cat $url/recon/subdomains.txt | waybackurls >> $url/recon/wayback/wayback_output.txt
sort -u $url/recon/wayback/wayback_output.txt
 
echo "[!] Taking and compiling all possible parameters found in wayback data..."
cat $url/recon/wayback/wayback_output.txt | grep '?*=' | cut -d '=' -f 1 | sort -u >> $url/recon/wayback/params/wayback_params.txt
for line in $(cat $url/recon/wayback/params/wayback_params.txt);do
	echo $line'=';
done

echo "[!] Running eyewitness against all compiled domains..."
gowitness file -f $url/recon/httprobe/alive_subdomains.txt -P $url/recon/gowitness
