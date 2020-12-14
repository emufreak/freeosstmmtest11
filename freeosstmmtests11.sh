#!/bin/bash

###############################################################################
################### FREEOSSTMSCAN11  0.1 - under GPLv3        #################
################### by Urs Schmid,                            #################
################### Thanks go to Mathias Gut                  #################
################### from the freecybersecurity.org Project    #################
################### Thanks to the community for the ideas     #################
################### for providing freebashskeleton            #################
################### integrated into this skeleton.            #################
###############################################################################

###############################################################################
#  INFORMATIONS                                                               #
#  Automizes Tasks required in an OSSTMM Data Network security audith         #
###############################################################################

#######################
### Preparing tasks ###
#######################

#Check root rights (sudo) before execution.
if [ $(id -u) -ne 0 ]; then
	echo "You need root rights (sudo)."
	exit
fi

#Check if a program is installed.
funcCheckProg() {
	local _program
	local _count
	local _i

	_program=(python3 vi emacs)
	for _i in "${_program[@]}"; do
		if [ -z $(command -v ${_i}) ]; then
			echo "${_i} is not installed."
			_count=1
		fi
	done

	if [[ ${_count} -eq 1 ]]; then
		exit
	fi
}

#Check if a program is installed via an input file.
funcCheckProg() {
	local _program
	local _proginst
	local _count
	local _line

	while read _line
	do
		_program=$(echo "${_line}" | awk -F ';;' '{print $1}')
		_proginst=$(echo "${_line}" | awk -F ';;' '{print $2}')

		if [ -z $(command -v ${_program}) ]; then
			echo "${_program} is not installed. Installation: ${_proginst}"
			_count=1
		fi

	done <./commandcheck.txt

	if [[ ${_count} -eq 1 ]]; then
		exit
	fi
}

#Read current date and time in hours and minutes into variable.
_TIME=$(date +%d.%m.%Y-%H:%M)

#Check if a folder exists and create otherwise.
#if ! [ -d "./inputs/temp" ]; then
#	mkdir ./inputs/temp
#fi


############################
### Integrated functions ###
############################

#. libraries/


###############################
### EXAMPLE TOOL USAGE TEXT ###
###############################

funcHelp() {
	echo "OSSTMM Scan for Data Networks Security"
	echo "Thanks to Matthias gut for "
	echo "OCSAF SKELETON 0.4 - GPLv3 (https://freecybersecurity.org)"
	echo "Use only with legal authorization and at your own risk!"
	echo "ANY LIABILITY WILL BE REJECTED!"
	echo ""
	echo "USAGE:"./osstmmscan11 [OPTIONS] -t target
	echo ""
	echo "LIMITATONS: Not all modules are fully supported"
	echo ""
	echo "EXAMPLE:"
	echo "  ./osstmmscan11 -a freecybersecurity.org"
	echo "  Complete Posture Review"
	echo "  ./osstmmscan11 -m 1 "
	echo "  Posture Review and Partial Logistics"
	echo "  ./osstmmscan11 -m 1,2.1,2.2a"
	echo "OPTIONS:"
	echo "  -h, help - this beautiful text"
	echo "  -a Run all available Modules "
	echo "  -d domain to scan if any"
	echo "  -i targetip"
	echo "  -m modules to run"
	echo "  -n nameservers for domain"
	echo "  -t reachable tcp port(s) comma separated"
	echo "  -u reachable udp port(s) comma separated" 
}


###############################
### GETOPTS - TOOL OPTIONS  ###
###############################

while getopts "am:h:d:i:t:u:n:" opt; do
	case ${opt} in
        	h) funcHelp; exit 1;;
		a) _MODULES="1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17";;
		m) _MODULES="$OPTARG";;
		i) _TARGET="$OPTARG";;
		d) _DOMAIN="$OPTARG";;
		u) _UDPPORTS="$OPTARG";;
		t) _TCPPORTS="$OPTARG";;
		n) _NAMESERVERS="$OPTARG";;
		\?) echo "**Unknown option**" >&2; echo ""; funcHelp; exit 1;;
        	#:) echo "**Missing option argument**" >&2; echo ""; funcHelp; exit 1;;
		*) funcHelp; exit 1;;
  	esac
	done
    	shift $(( OPTIND - 1 ))

#Check if _CHECKARG1 is set
if [ "${_MODULES}" == "" ]; then
	echo "**No modules set**"
	echo "You must either specify argument a or m"
	funcHelp
	exit 1
fi

#Check if _CHECKARG1 is set
if [ "${_TARGET}" == "" ]; then	
	echo "**No target set**"
	echo "Please specify a target with argument t"
	funcHelp
	exit 1
fi


###############
### COLORS  ###
###############

#Colors directly in the script.
if [[ ${_COLORS} -eq 1 ]]; then
	cOFF=''
	rON=''
	gON=''
	yON=''
else
	cOFF='\e[39m'	  #color OFF / Default color
	rON='\e[31m'	  #red color ON
	gON='\e[32m'	  #green color ON
	yON='\e[33m'	  #yellow color ON
fi


#As color library.
. colors.sh


############################
#### your cool functions ###
############################

# My function for ...
# Naming convention for functions funcFunctionname() - z.B. funcMycheck()

funcmodule02() {
  echo ""
  echo ""
  echo ""
  echo ""
  echo "#####################################################################################"	
  echo "# Running all checks for module 2 (logistics)                                       #" 
  echo "#####################################################################################"
  echo ""
  funcmodule021
  funcmodule022
  funcmodule023
}

funcmodule021() {
  echo ""
  echo "#####################################################################################"	
  echo "# Running all checks for module 2.1 (logistics/framework)                           #"
  echo "#####################################################################################"	  
  echo ""
  funcmodule021c
  funcmodule021d
  funcmodule021j
}

funcmodule021c() {
  echo ""
  echo "######################################################################################"
  echo "# 2.1c: Verify the owner of the targets from network registration information        #"
  echo "######################################################################################"
  echo ""
  echo "whois $_TARGET"
  whois $_TARGET
}

funcmodule021d() {
  echo ""
  echo "######################################################################################"
  echo "# 2.1d: Verify the owner of the target domains from domain registration information. #"
  echo "######################################################################################"
  echo ""
  if [ $_DOMAIN == ""]; then
    echo "Nothing to do. No target domain specified"
  else
    echo "whois $_DOMAIN"
    whois $_DOMAIN
  fi
}

funcmodule021j() {
  echo ""
  echo "######################################################################################"
  echo "# 2.1j: Verify that reverse name lookups of target system addresses correspond with  #"
  echo "#       the scope and the scope owner                                                #"
  echo "######################################################################################"
  echo ""
  echo "nslookup $_TARGET"
  nslookup $_TARGET
}

funcmodule022() {
  echo ""
  echo "#####################################################################################"	
  echo "# Running all checks for module 2.2 (Logistics/Network Quality)                     #"
  echo "#####################################################################################"	  
  echo ""
  funcmodule022a
}

funcmodule022a() {
  echo ""
  echo "######################################################################################"
  echo "# 2.2a: Measure the rate of speed and packet loss to the scope for a requested       #"
  echo "#       service in TCP, UDP,and ICMP both as a whole service request and as a        #"
  echo "#       request/response pair. Repeat eachrequest in succession at least 100 times   #"
  echo "#       and record the average for both whole servicerequests and packet responses   #" 
  echo "#       for each of the three protocols.                                             #"
  echo "#       LIMITATION: Complete Service request has to be tested manually               #"
  echo "######################################################################################"
  echo ""

  echo "hping3 --icmp -c 100 $_TARGET"
  hping3 --icmp -c 100 $_TARGET
  echo ""

  
  if [ $_UDPPORTS == ""]; then
    echo "Cannot do UDP test without open upd ports."
    echo ""  
  else
    for udpport in $_UDPPORTS
    do
      echo "hping3 --udp $_TARGET --destport $udpport --count 100"
      hping3 --udp $_TARGET --destport $udpport --count 100 --data 1024
      echo ""
    done
  fi

  if [ $_TCPPORTS == ""]; then
    echo "Cannot do TCP test without open tcp ports."
    echo ""  
  else
    for tcpport in $_TCPPORTS
    do
      echo "hping3 --syn $_TARGET --destport $tcpport --count 100 --data 1024"
      hping3 --syn $_TARGET --destport $tcpport --count 100 --data 1024
      echo ""
    done	  
  fi
}

funcmodule023() {
  echo ""
  echo "#####################################################################################"	
  echo "# Running all checks for module 2.3 (Time)                                          #"
  echo "#####################################################################################"	  
  echo ""
  funcmodule023b
  funcmodule023c
}

funcmodule023b() {
  echo ""
  echo "######################################################################################"
  echo "# 2.3b: Identify the Time To Live (TTL) distance to the gateway and the targets      #"
  echo "######################################################################################"
  echo ""

  echo "traceroute $_TARGET"
  traceroute $_TARGET
  echo ""
  
  if [ ${_UDPPORTS} == "" ]; then
    echo "Cannot do UDP test without open udp ports."
    echo ""  
  else
    for udpport in $_UDPPORTS
    do
      echo "traceroute --udp --port=$udpport $_TARGET"
      traceroute --udp --port=$udpport $_TARGET
      echo ""
    done
  fi

  if [ ${_TCPPORTS} == "" ]; then
    echo "Cannot do TCP test without open tcp ports."
    echo ""  
  else
    for tcpport in $_TCPPORTS
    do
      echo "traceroute --tcp --port=$tcpport $_TARGET"
      traceroute --tcp --port=$tcpport $_TARGET
      echo ""
    done
  fi
}

funcmodule023c() {
  echo ""
  echo "######################################################################################"
  echo "# 2.3c: Assure the Analyst’s clock is in sync with the time of the targets.          #"
  echo "######################################################################################"
  echo ""

  echo "hping3 --icmptype 13 --icmpcode 0 $_TARGET -c 1"
  hping3 --icmptype 13 --icmpcode 0 $_TARGET -c 1
  echo "" 
  result=$(hping3 --icmptype 13 --icmpcode 0 $_TARGET -c 1)

  originate=$(echo $result \
	  | awk '/Originate/ { gsub(".*Originate=","",$0); gsub(" .*","",$0); print $0; }')  

  if [ $originate == ""]; then
    echo "Cannot get time using ICMP flag. Try something else manually!"
  else
    echo "Originate=$originate ms"
  
    receive=$(echo $result \
    	  | awk '/Receive/ { gsub(".*Receive=","",$0); gsub(" .*","",$0); print $0; }')
    echo "Receive=$receive ms"
  
    rtt=$(echo $result \
	  | awk '/tsrtt/ { gsub(".*tsrtt=","",$0); gsub(" .*","",$0); print $0; }')
    echo "rtt=$rtt ms"
  
    timediff=$(( ( $receive - $originate - $rtt / 2) / 1000  )) 
  
    while true; do
      read -p "Set time back $timediff seconds?" yn
      case $yn in
          [Yy]* )  date $(date +%m%d%H%M%Y.%S -d "$timediff seconds ago"); break;;
          [Nn]* ) break;;
          * ) echo "Please answer yes or no.";;
      esac
    done
  fi

}

funcmodule04() {
  echo ""
  echo ""
  echo ""
  echo ""
  echo "#####################################################################################"	
  echo "# Running all checks for module 4 (Visibility Audit)                                #" 
  echo "#####################################################################################"
  echo ""
  funcmodule041
  funcmodule042
}

funcmodule041() {
  echo ""
  echo "#####################################################################################"	
  echo "# Running all checks for module 4.1 (Visibility Audit/Network Surveying)            #"
  echo "#####################################################################################"	  
  echo ""
  funcmodule041c
  funcmodule041d
  funcmodule041f
}

funcmodule041c() {
  echo ""
  echo "######################################################################################"
  echo "# 4.1c: Query all name servers and the name servers of the ISP or hosting provider,  #"
  echo "#       if available, for corresponding A, AAAA, and PTR records as well as ability  #"
  echo "#       to perform zone transfers to determine the existence of all targets in the   #"
  echo "#       network and any related redundancies, loadbalancing, caching, proxying, and  #"
  echo "#       virtual hosting.                                                             #"
  echo "######################################################################################"
  echo ""


  #if [ "${_MODULES}" == "" ]; then
  if [ "${_NAMESERVERS}" == "" ] || [ "${_DOMAIN}" == "" ]; then
    echo "No Nameservers and(or Domain for test provided. Skipping ..."
    echo ""    
  else
    for nameserver in $_NAMESERVERS
    do
      echo "dig AXFR $_DOMAIN @$nameserver"
      dig AXFR $_DOMAIN @$nameserver
      echo ""
      echo "dig $_DOMAIN @$nameserver A"
      dig $_DOMAIN @$nameserver A
      echo ""
      echo "dig $_DOMAIN @$nameserver AAAA"
      dig $_DOMAIN @$nameserver AAAA
      echo ""
      echo "dig www.$_DOMAIN @$nameserver A"
      dig www.$_DOMAIN @$nameserver A
      echo ""
      echo "dig www.$_DOMAIN @$nameserver AAAA"
      dig www.$_DOMAIN @$nameserver AAAA
      echo ""      
      echo "dig $_DOMAIN @$nameserver PTR"
      dig $_DOMAIN @$nameserver PTR
      echo ""
      echo "dig www.$_DOMAIN @$nameserver PTR"
      dig www.$_DOMAIN @$nameserver PTR
            
    done
  fi
}

funcmodule041d() {
  echo ""
  echo "######################################################################################"
  echo "# 4.1d: Verify broadcast requests and responses from all targets.                    #"
  echo "######################################################################################"
  echo ""
  echo "arp-scan $_TARGET"
  arp-scan $_TARGET  
}

funcmodule041f() {
  echo ""
  echo "######################################################################################"
  echo "# 4.1f: Verify ICMP responses for ICMP types 0-255 and ICMP codes 0-2 from all       #"
  echo "#       targets.                                                                     #"
  echo "######################################################################################"
  echo ""
  

  for icmptype in {0..255}
  do
    for icmpcode in {0..2}
    do
      echo "hping for icmp type $icmptype code $icmpcode"
      hping3 --icmptype $icmptype --icmpcode $icmpcode --force-icmp -c 3 $_TARGET
    done
  done
}


funcmodule042() {
  echo ""
  echo "#####################################################################################"	
  echo "# Running all checks for module 4.2 (Visibility Audit/Enumeration)                  #"
  echo "#####################################################################################"	  
  echo ""
  funcmodule042f
  funcmodule042g
  funcmodule042j
  funcmodule042lm
}


funcmodule042f() {
  echo ""
  echo "######################################################################################"
  echo "# 4.2f: Verify all responses from UDP packet requests to ports 0-65535.              #"
  echo "######################################################################################"
  echo ""
  echo "nmap -sU $_TARGET"  
  nmap -sU $_TARGET
}

funcmodule042g() {
  echo ""
  echo "######################################################################################"
  echo "# 4.2g: Verify responses to UDP packet requests FROM SOURCE ports 0, 53, 139, and    #"
  echo "#       161 to 0, 53, 69,131, and 161.                                               #"
  echo "######################################################################################"
  echo ""
  echo "nmap -sU --source-port 0 --reason -p0,53,69,131,161 $_TARGET"  
  nmap -sU --source-port 0 --reason -p0,53,69,131,161 $_TARGET 
  echo "nmap -sU --source-port 53 --reason -p0,53,69,131,161 $_TARGET"  
  nmap -sU --source-port 53 --reason -p0,53,69,131,161 $_TARGET 
  echo "nmap -sU --source-port 69 --reason -p0,53,69,131,161 $_TARGET"  
  nmap -sU --source-port 69 --reason -p0,53,69,131,161 $_TARGET 
  echo "nmap -sU --source-port 131 --reason -p0,53,69,131,161 $_TARGET"  
  nmap -sU --source-port 131 --reason -p0,53,69,131,161 $_TARGET 
  echo "nmap -sU --source-port 161 --reason -p0,53,69,131,161 $_TARGET"  
  nmap -sU --source-port 161 --reason -p0,53,69,131,161 $_TARGET 
}

funcmodule042j() {
  echo ""
  echo "######################################################################################"
  echo "# 4.2j: Verify responses from TCP SYN packet requests to ports 0-65535               #"
  echo "# 4.3:  Identify targets TTL response, system uptime, services, applications,        #"
  echo "#       application faults, and correlate this with the responses from system and    #"
  echo "#       service fingerprinting tools.                                                #"
  echo "######################################################################################"
  echo ""
  echo "nmap -A -p- $_TARGET"
  nmap -A -p- $_TARGET
}

funcmodule042lm() {
  echo ""
  echo "######################################################################################"
  echo "# 4.2l: Identify TCP ISN sequence number predictability for all targets.             #"
  echo "# 4.2m: Verify IPID increments from responses for all targets                        #"
  echo "######################################################################################"
  echo ""
  echo "ping $_TARGET -c 5"
  ping $_TARGET -c 5
}


funcmodule05() {
  echo ""
  echo ""
  echo ""
  echo ""
  echo "#####################################################################################"	
  echo "# Running all checks for module 5 (Access Verification)                             #" 
  echo "#####################################################################################"
  echo ""
  funcmodule052
}

funcmodule052() {
  echo ""
  echo "#####################################################################################"	
  echo "# Running all checks for module 5.2 (Access Verification/Services)                  #"
  echo "#####################################################################################"	  
  echo ""
  funcmodule052d
}

funcmodule052d() {
  echo ""
  echo "######################################################################################"
  echo "# 5.2d: Verify system uptime compared to the latest vulnerabilities and patch        #"
  echo "#       releases.                                                                    #"
  echo "######################################################################################"
  echo ""

  if [ $_TCPPORTS == ""]; then
    echo "Cannot do TCP test without open tcp ports."
    echo ""  
  else
    for tcpport in $_TCPPORTS
    do
      echo "hping3 -S -p $tcpport --tcp-timestamp -c 5 $_TARGET"
      hping3 -S -p $tcpport --tcp-timestamp -c 5 $_TARGET
      echo ""
    done
  fi
}

funcmodule07() {
  echo ""
  echo ""
  echo ""
  echo ""
  echo "#####################################################################################"	
  echo "# Running all checks for module 7 (Controls Verification)                           #" 
  echo "#####################################################################################"
  echo ""
  funcmodule072
}

funcmodule072() {
  echo ""
  echo "#####################################################################################"	
  echo "# Running all checks for module 7.2 (Controls Verification/Confidentiality)         #"
  echo "#####################################################################################"	  
  echo ""
  funcmodule072bc
}

funcmodule072bc() {
  echo ""
  echo "######################################################################################"
  echo "# 7.2b: Verify the acceptable methods used for confidentiality.                      #"
  echo "# 7.3b: Test the strength and design of the encryption or obfuscation method.        #"
  echo "######################################################################################"
  echo ""
  echo "sslscan $_TARGET"
  sslscan $_TARGET
}
############
### MAIN ###
############

echo ""
echo "##########################################"
echo "####  FREE OSSTMM11 AUDIT GPL V3      ####"
echo "##########################################"
echo ""

IFS=","
for module in $_MODULES
do
  case "$module" in
    2) funcmodule02;;
    2.1) funcmodule021;;
    2.1c) funcmodule021c;;
    2.1d) funcmodule021d;;
    2.1j) funcmodule021j;;
    2.2) funcmodule022;;
    2.2a) funcmodule022a;;
    2.3) funcmodule023;;
    2.3b) funcmodule023b;;
    2.3c) funcmodule023c;;
    4) funcmodule04;;
    4.1) funcmodule041;;
    4.1c) funcmodule041c;;
    4.1d) funcmodule041d;;
    4.1f) funcmodule041f;;
    4.2) funcmodule042;;
    4.2f) funcmodule042f;;
    4.2g) funcmodule042g;;
    4.2j) funcmodule042j;;
    4.2l) funcmodule042lm;;
    4.2m) funcmodule042lm;;
    4.3) funcmodule042j;;
    5) funcmodule05;;
    5.2) funcmodule052;;
    5.2d) funcmodule052d;;  
    7) funcmodule07;;
    7.2) funcmodule072;;
    7.2b) funcmodule072bc;;
    7.2c) funcmodule072bc;;
  esac
done

################### END ###################
