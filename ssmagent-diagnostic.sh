#!/bin/bash

# This scripts contains function to generate report and collect logs related to ssm agent


# Diagnostic Test Function

runtests()
{

echo "
    ___ _       _______    _____            __                         __  ___                                 
   /   | |     / / ___/   / ___/__  _______/ /____  ____ ___  _____   /  |/  /___ _____  ____ _____ ____  _____
  / /| | | /| / /\__ \    \__ \/ / / / ___/ __/ _ \/ __ '__ \/ ___/  / /|_/ / __ '/ __ \/ __ '/ __ '/ _ \/ ___/
 / ___ | |/ |/ /___/ /   ___/ / /_/ (__  ) /_/  __/ / / / / (__  )  / /  / / /_/ / / / / /_/ / /_/ /  __/ /    
/_/  |_|__/|__//____/   /____/\__, /____/\__/\___/_/ /_/ /_/____/  /_/  /_/\__,_/_/ /_/\__,_/\__, /\___/_/     
                             /____/                                                         /____/             

"

    Region=$fetchregion
    METADATA_URL=169.254.169.254
    ec2end=ec2messages.$Region.amazonaws.com
    ssmend=ssm.$Region.amazonaws.com
    ssmmessagesend=ssmmessages.$Region.amazonaws.com
    HTTPSPORT=443
    HTTPPORT=80
    TIMEOUT=1

    printf "Check|Value|Note\n" >> /tmp/ssmscript-output.txt
    echo "-----|-----|-----" >> /tmp/ssmscript-output.txt
    echo "   |    |    |" >> /tmp/ssmscript-output.txt

    #-------Test1-------

    Test1="Testing metadata endpoint"
    echo " "
    if nc -w $TIMEOUT -z $METADATA_URL $HTTPPORT; then
        Result1="Pass"
        Note1="N/A"
    else
        Result1="Fail"
        Note1="Connectivity failed to metadata service"
    fi
    printf "$Test1|$Result1|$Note1\n" >> /tmp/ssmscript-output.txt


    #-------Test2-------

    Test2="Getting IAM Role Attached"
    IAM_ROLE=$(curl -s  http://169.254.169.254/latest/meta-data/iam/security-credentials/)
    if [[ $IAM_ROLE == *"Not Found"* ]];then
     Result2="Not Found"
    else
     Result2="$IAM_ROLE"
    fi
    Note2="Require the minimum of policies as of Amazon Managed Policy,AmazonSSMManagedInstanceCore."
    printf "$Test2|$Result2|$Note2\n"  >> /tmp/ssmscript-output.txt


    #-------Test3-------

    Test3="Testing ec2messages endpoint Connectivity"
    if nc -w $TIMEOUT -z $ec2end $HTTPSPORT; then
     Result3="Pass"
     Note3="N/A"
    else
     Result3="Fail"
     Note3="Connectivity failed to ec2messages.$Region.amazonaws.com"
    fi
    printf "$Test3|$Result3|$Note3\n" >> /tmp/ssmscript-output.txt

    #-------Test4-------

    Test4="Testing SSM endpoint Connectivity"
    if nc -w $TIMEOUT -z $ssmend $HTTPSPORT; then
     Result4="Pass"
     Note4="N/A"
    else
     Result4="Fail"
     Note4="Connectivity failed to ssm.$Region.amazonaws.com"
    fi
    printf "$Test4|$Result4|$Note4\n" >> /tmp/ssmscript-output.txt

    #-------Test5-------

    Test5="Testing ssmmessages endpoint Connectivity"
    if nc -w $TIMEOUT -z $ssmmessagesend $HTTPSPORT; then
     Result5="Pass"
     Note5="N/A"
    else
     Result5="Fail"
     Note5="Connectivity failed to ssmmessages.$Region.amazonaws.com"
    fi
    printf "$Test5|$Result5|$Note5\n" >> /tmp/ssmscript-output.txt


    #-------Test6-------

    Test6="SSM agent Service Running"
    if [ -f /usr/bin/yum ] || [ -f /usr/bin/zypper ]; # For Redhat Variants
    then 
     Test6="SSM agent service status"
     rpm -qa | grep amazon-ssm-agent > /dev/null 2>/dev/null
     if [ $? -ne 0 ];then
      Result6="Not Installed"
     else
      is_running=$(ps aux | grep -v grep | grep -w amazon-ssm-agent | wc -l | awk '{print $1}')
      if [ $is_running != "0" ]; then
       Result6="Active"
      else
       Result6="Inactive" 
      fi      
     fi
    elif [ -f /etc/debian_version ];then #For Ubuntu. Covering both snap and dpkg installation types.
     if [ -f /usr/bin/snap ];
     then
      snap info amazon-ssm-agent > /dev/null 2>/dev/null
      if [ $? -eq 0 ];then
       snap services amazon-ssm-agent.amazon-ssm-agent | grep -w "active" > /dev/null 2>/dev/null
       if [ $? -eq 0 ];then
        Result6=Active
       else
        Result6=Inactive
       fi 
      else
       Result6="Not Installed"
      fi
     else
      if [ $(dpkg-query -W -f='${Status}' amazon-ssm-agent 2>/dev/null | grep -c "ok installed") -eq 1 ];
      then
       Result6=`systemctl is-active  amazon-ssm-agent`
      else
       Result6="Not Installed"
      fi
     fi
    else
     Results6="Unable to determine OS"
    fi 
    Note6=N/A 
    printf "$Test6|$Result6|$Note6\n" >> /tmp/ssmscript-output.txt

    #-------Test7-------

    Test7="SSM Agent Proxy Settings"
    sudo xargs --null --max-args=1 < /proc/$(pidof amazon-ssm-agent)/environ | grep -e "http_proxy"
    if [ $? -eq 0 ];then
     Results7a=`sudo xargs --null --max-args=1 < /proc/$(pidof amazon-ssm-agent)/environ | grep -e "http_proxy"`
     Note7=N/A
    else
     Results7a="http_proxy=NULL"
     Note7="There is no Proxy settings for SSM agent"
    fi
    sudo xargs --null --max-args=1 < /proc/$(pidof amazon-ssm-agent)/environ | grep -e "https_proxy"
    if [ $? -eq 0 ];then
     Results7b=`sudo xargs --null --max-args=1 < /proc/$(pidof amazon-ssm-agent)/environ | grep -e "https_proxy"`
     Note7=N/A
    else
     Results7b="http_proxys=NULL"
     Note7="There is no Proxy settings for SSM agent"
    fi
    sudo xargs --null --max-args=1 < /proc/$(pidof amazon-ssm-agent)/environ | grep -e "no_proxy"
    if [ $? -eq 0 ];then
     Results7c=`sudo xargs --null --max-args=1 < /proc/$(pidof amazon-ssm-agent)/environ | grep -e "no_proxy"`
    else
     Results7c="no_proxy=NULL"
    fi
    printf "$Test7|$Results7a,$Results7b,$Results7c|$Note7\n" >> /tmp/ssmscript-output.txt


    #-------Test8-------


    Test8="System Wide Proxy Settings"
    env | grep -e "http_proxy"
    if [ $? -eq 0 ];then
     Results8a=`env | grep -e "http_proxy"`
     Note8=N/A
    else
     Results8a="http_proxy=NULL"
     Note8="No System wide proxy settings detected"
    fi
    env | grep -e "https_proxy"
    if [ $? -eq 0 ];then
     Results8b=`env | grep -e "https_proxy"`
     Note8=N/A
    else
     Results8b="https_proxy=NULL"
     Note8="No System Wide proxy settings detected"
    fi
    env | grep -e "no_proxy"
    if [ $? -eq 0 ];then
     Results8c=`env | grep -e "no_proxy"`
    else
     Results8c="no_proxy=NULL"
    fi
    printf "$Test8|$Results8a,$Results8b,$Results8c|$Note8\n" >> /tmp/ssmscript-output.txt


    #-------Test9------

    Test9="DNS server details"
    nameservers=($(grep nameserver /etc/resolv.conf | head -n5|cut -d ' ' -f2))
    Results9=${nameservers[@]}
    Note9=N/A
    printf "$Test9|$Results9|$Note9\n" >> /tmp/ssmscript-output.txt


    #-------Test10------

    Test10=""Resolving" $ssmend"
    ip=($(dig +short $ssmend))
    if (( ${#ip[@]} ));then
     Results10=${ip[@]}
     Note10="N/A"
    else
     Results10="Null"
     Note10="Couldnt resolve"
    fi
    printf "$Test10|$Results10|$Note10\n" >> /tmp/ssmscript-output.txt
    cat /tmp/ssmscript-output.txt  | column -t -s "|"
    rm -rf /tmp/ssmscript-output.txt
    echo " "

}

# Function to collect Logs

CollectLogs()
{
read -t 4 -p "Press S for SSM agent Logs. Press R for Run Command Logs.Values are case sensitive: " REPLY
echo " No Input Provided. The default value is ${REPLY:=S}."

if [ $REPLY == "S" ];then
 tar -cf AWS_SSMLOGS_$(date +%F).tar --absolute-names /etc/amazon/ssm/ /var/log/amazon/ssm/ /var/lib/amazon/ssm
 echo "Logs stored in the current working directory : AWS_SSMLOGS_$(date +%F).tar"
elif [ $REPLY == "R" ];then
 echo -n "Enter the Command execution ID: ";
 read;
 ExecID=$REPLY
 instance=`curl -s http://169.254.169.254/latest/meta-data/instance-id`
 #check logs exist
 if [ -e /var/lib/amazon/ssm/$instance/document/orchestration/$ExecID/ ];then
  tar -cf AWS_RunCommand_Logs_$ExecID.tar  --absolute-names /var/lib/amazon/ssm/$instance/document/orchestration/$ExecID/
  echo "Logs stored in the current working directory : AWS_RunCommand_Logs_$ExecID.tar"
 else
  echo "Logs cannot be found for the execution id provided" 
 fi
else
 echo "Wrong input provided"
fi  
}

# Function to Enable/Disable Debug Logs

DebugLogs()
{
echo " Not available with this version yet. Wait for the next release"  
}


# Help function

GetHelp()
{
   # Display Help
   echo "Description of the script options here."
   echo
   echo "Syntax: ssmagent-toolkit-Linux.sh [-h|r|l]"
   echo "options:"
   echo "-h     Print this Help."
   echo "-r     Enter Region. Useful with On Premise Instances. This will generate the Diagnostic report."
   echo "-l     Collect Logs."
   echo "-d     (Not available yet) Enable or disable Debugging Logs for SSM Agent."
   echo
}


# Process the input options. Add options as needed. 
# Get the options

while getopts ":hr:ld" option; do
 case $option in
  h)
    GetHelp
    ;;
  r)
    fetchregion=$OPTARG
    runtests $fetchregion
    ;;
  l)
    CollectLogs
    ;;
  d)
    DebugLogs
    ;;  
  :)
    echo "Missing option argument for -$OPTARG" >&2; 
    exit 1
    ;;
  esac
done

if ((OPTIND == 1))
then
    fetchregion=$(curl -s  http://169.254.169.254/latest/dynamic/instance-identity/document | grep region | cut -d " " -f5 | tr -d '",')
    runtests $fetchregion
fi
