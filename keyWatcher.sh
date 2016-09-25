#!/bin/bash 
# 20160908 v0.1 by Jackie Chen: update profile, score requests
# 20160909 v0.2 by Jackie Chen: import, export profile, delete search job, html format email report
# 20160220 v0.3 by Jackie Chen: check and view the exposed AWS key in trusted advisor

highlight() 
{ 
	COLOR='\033[1;33m'
    NC='\033[0m'
    printf "${COLOR}$1${NC}\n"
}

usage()
{
	echo ""
	highlight "./keyWatcher <update_profile|export_profile|import_profile|show_profile|delete_profile|score_request|house_keeping|view_exposed_key|check_exposed_key>"
}

check_dep()
{
	echo ""
	highlight ">>> Checking dependencies"
	if [[ ! `netstat -an | grep 6379` ]]; then
		echo "Redis server is not running, exit."
		exit 1
	fi
	if [ ! -f /usr/local/bin/redis-cli ]; then
  		echo "Installing redis-cli."
  		yum -y install gcc git
  		git clone http://github.com/antirez/redis.git ~/redis
  		make -C ~/redis install redis-cli
  		if [ $? -ne 0 ]; then exit 1; fi
	fi
	if [ ! -f /usr/bin/jq ]; then
		echo "Installing jq."
		yum -y install jq
	fi
	echo "All good."
}

check_connection()
{
	echo ""
	highlight ">>> Checking Internet connection"
	if [[ ! `curl -s --noproxy ipecho.net  http://ipecho.net/plain | grep '.'` ]]; then
		echo "No Internet connection, checking proxy."	
		if [[ `export | grep http_proxy` ]]; then
			echo "Found proxy."
			# format: http_proxy="http://host:port"
  			PROXY="-x ${http_proxy}"
  			echo "Trying proxy."
  			if [[ ! `curl $PROXY -s http://ipecho.net/plain | grep '.'` ]]; then
  				echo "Still no Internet connection, exit."
  				exit 1
  			else
  				echo "Internet connection seems OK with proxy."
  			fi
  		else
  			echo "No proxy either, exit."
  			exit 1
  		fi
  	else
  		echo "Internet connection seems OK without proxy."
  		PROXY=""
	fi	
}

sumo_search()
{
	echo ""
	highlight ">>> Starting Sumo search"
	echo "Checking sumo credentials."
	# Check Sumo credential
	if [[ ! `export | grep SUMO_ACCESS` ]]; then
		echo "Not found sumo credential, please set it up: 'export SUMO_ACCESS=<accessId>:<accessKey>'"
		exit 1
	fi

 	# Sumo API endpoint
	SUMO_ENDPOINT="https://api.au.sumologic.com/api/v1/search/jobs"

	# Default search for the past 10 minutes
	# example: 1 day ago
	TIME=${1:-"10 min ago"}
	KEY=${2:-""}

	# Polling interval in seconds
	WAIT_FOR="10"

	# Setup search time range
	FROM_TIME=`date  "+%Y-%m-%dT%R:%S" -d "$TIME"`
	TO_TIME=`date  "+%Y-%m-%dT%R:%S"`

	# Generate search params file
	cat > .$$.sumo_search.json <<-EOF
		{
  			"query": "_index=cloudtrail_logs ${KEY}| json auto keys \"userIdentity.accessKeyId\", \"sourceIPAddress\", \"userAgent\", \"awsRegion\", \"eventName\" as accessKeyId, sourceIPAddress, userAgent, awsRegion, eventName",
  			"from": "${FROM_TIME}",
  			"to": "${TO_TIME}",
  			"timeZone": "Australia/Sydney"
		}
	EOF

	echo "Searching Sumo logs between now and $TIME."
	JOB_ID=`curl $PROXY -s -b cookies.txt -c cookies.txt -H 'Content-type: application/json' -H 'Accept: application/json' -X POST -T .$$.sumo_search.json --user "$SUMO_ACCESS" "$SUMO_ENDPOINT" | jq -r .id`
	echo "Job ID: $JOB_ID"
	echo "Process ID: $$"

	JOB_STATUS="STARED"
	N=0
	while [ "${JOB_STATUS}" != "DONE GATHERING RESULTS" ]
	do
  		sleep $WAIT_FOR
  		let N++
  		echo -ne "Search job status is ${JOB_STATUS} (${N}/${TIMEOUT})\r"
  		JOB_STATUS=`curl $PROXY -s -b cookies.txt -c cookies.txt -H 'Accept: application/json' --user "$SUMO_ACCESS" $SUMO_ENDPOINT/${JOB_ID}| jq -r .state`
  		if [ $N -gt $TIMEOUT ]; then echo "Search timed out, exit."; exit 1; fi
	done

	echo
	echo "Generating search result."
	curl $PROXY -s -b cookies.txt -c cookies.txt -H 'Accept: application/json' --user "$SUMO_ACCESS" "$SUMO_ENDPOINT/${JOB_ID}/messages?offset=0&limit=100000" -o .$$.sumo_output

	echo "Deleting search job."
	curl $PROXY -s -b cookies.txt -c cookies.txt -H 'Accept: application/json' --user "$SUMO_ACCESS" -X DELETE "$SUMO_ENDPOINT/${JOB_ID}" > /dev/null 2>&1
}

extract_output()
{
	echo ""
	highlight ">>> Extracting the sumo search results"
	cat .$$.sumo_output | jq -r '.messages[].map._raw' | jq -r '"[Key]" + .userIdentity.accessKeyId + ":" + "[Account]" + .recipientAccountId + ":" + "[Type]" + .userIdentity.type + ":" + "[Username]" + .userIdentity.userName + ":" + "[Region]" + .awsRegion + ":" + "[Ip]" + .sourceIPAddress + ":" + "[Agent]" + .userAgent + ":" + "[Eventsource]" + .eventSource + ":" + "[Eventname]" + .eventName'  | tr ' ' '-'  > .$$.extracted_output
	RAW_RECORDS=`cat .$$.extracted_output | wc -l`
	cp .$$.extracted_output .$$.raw_output
	echo "Total raw records: $RAW_RECORDS"
	# Exclude the type that generates dynamic access keys
	sed -i "/\[Type\]AssumedRole/d" .$$.extracted_output
	sed -i "/\[Type\]SAMLUser/d" .$$.extracted_output
	sed -i "/\[Type\]Root/d" .$$.extracted_output
	sed -i "/\[Key\]:\[Account\]/d" .$$.extracted_output
	awk '!seen[$0]++' .$$.extracted_output > tmp && mv tmp .$$.extracted_output
	RECORDS=`cat .$$.extracted_output | wc -l` 
	echo "Total extracted records: $RECORDS"
}

house_keeping()
{
	echo ""
	highlight ">>> Removing temp files"
	rm -rf .*sumo* .*extract* .*score* .*raw* .*suspicious* .*expose*
	echo done!
}

update_profile()
{
	echo ""
	highlight ">>> Updating key profile"
	if [ "$RECORDS" == "0" ]; then
		echo "Extracted records is 0, exit."
		echo ""
		exit 0
	fi
	for (( i=1; i<=$RECORDS; i++ ))
	do 
		echo -ne "Processing ${i}/$RECORDS\r"
		METADATA=`sed -n ${i}p .$$.extracted_output`
		
		KEY=`echo $METADATA | cut -d':' -f1`
		ACCOUNT=`echo $METADATA | cut -d':' -f2`
		USER=`echo $METADATA | cut -d':' -f4`
		REGION=`echo $METADATA | cut -d':' -f5`
		IP=`echo $METADATA | cut -d':' -f6`
		AGENT=`echo $METADATA | cut -d':' -f7`
		EVENT=`echo $METADATA | cut -d':' -f9`
		
		redis-cli incrby $KEY:$REGION 1 > /dev/null
		redis-cli incrby $KEY:$ACCOUNT:$USER 1 > /dev/null
		redis-cli incrby $KEY:$IP 1 > /dev/null
		redis-cli incrby $KEY:$AGENT 1 > /dev/null
		redis-cli incrby $KEY:$EVENT 1 > /dev/null
	done
	echo
	echo done!
}

show_profile()
{
	echo ""
	highlight ">>> Listing key profile"
	echo "Type the key or keyword you want to check(* for all keys), followed by [ENTER]:"
    read KEY 
	redis-cli keys "*${KEY}*"
}

delete_profile()
{
	echo ""
	highlight ">>> Deleting key profile"
	echo "Type the key you want to delete(* for all keys), followed by [ENTER]:"
    read KEY 
	redis-cli --raw keys "*${KEY}*" | xargs redis-cli del
}

export_profile()
{
	echo ""
	highlight ">>> Exporting key profiles"
	PROFILE=profile-`date +%Y-%m-%d-%R`
	for key in `redis-cli --raw keys "*"`; do
		echo "redis-cli set \"$key\" 1" >> $PROFILE
	done
	echo done! The profile name is $PROFILE
}

import_profile()
{
	echo ""
	highlight ">>> Importing key profiles"
	echo "Please type which profile file you want to import: "
	ls profile-*
	if [ $? -ne 0 ]; then echo ""; exit 1; fi
	read PROFILE
	if [ ! -f $PROFILE ]; then
		echo "No profile files are found! exit."
		echo ""
		exit 1
	fi
	sh $PROFILE
}

check_profile()
{
	echo ""
	highlight ">>> Checking key profiles"
	if [[ `redis-cli keys "*"` == "" ]]; then
		echo "No key profiles are found, exit."
		echo ""
		mail -s "[keyWatcher] No key profiles are found" $RECIPIENT <<< "Please check!"
		exit 1
	else
		echo "Key profiles are found."
	fi	
}

score_request()
{
	echo ""
	highlight ">>> Scoring requests"

	if [ "$RECORDS" == "0" ]; then
		echo "Extracted records is 0, exit."
		echo ""
		exit 0
	fi
	for (( i=1; i<=$RECORDS; i++ ))
	do 
		SCORE=0
		SCORE_DETAILS="("
		echo -ne "Processing ${i}/$RECORDS\r"
		METADATA=`sed -n ${i}p .$$.extracted_output`
		
		KEY=`echo $METADATA | cut -d':' -f1`
		USER=`echo $METADATA | cut -d':' -f2`
		REGION=`echo $METADATA | cut -d':' -f3`
		IP=`echo $METADATA | cut -d':' -f4`
		AGENT=`echo $METADATA | cut -d':' -f5`
		EVENT=`echo $METADATA | cut -d':' -f6`
		
		REGION_MATCH=`redis-cli get $KEY:region:$REGION`
		if [ "$REGION_MATCH" != "" ]; then 
			let SCORE=$SCORE+25
		else
			SCORE_DETAILS+="region does not match,"
		fi
		IP_MATCH=`redis-cli get $KEY:sourceip:$IP`
		if [ "$IP_MATCH" != "" ]; then
			let SCORE=$SCORE+40
		else
			SCORE_DETAILS+="IP does not match,"
		fi
		AGENT_MATCH=`redis-cli incrby $KEY:agent:$AGENT`
		if [ "$AGENT_MATCH" != "" ]; then
			let SCORE=$SCORE+25
		else
			SCORE_DETAILS+="agent does not match,"
		fi
		EVENT_MATCH=`redis-cli incrby $KEY:event:$EVENT`
		if [ "$EVENT_MATCH" != "" ]; then 
			let SCORE=$SCORE+10
		else
			SCORE_DETAILS+="event does not match,"
		fi
		SCORE_DETAILS+=")"
		echo ${METADATA}:${SCORE}:${SCORE_DETAILS} >> .$$.requests_score
		if [ $SCORE -lt 70 ]; then
			echo
			highlight "suspicious request: [Score:${SCORE}]${SCORE_DETAILS} Request: ${METADATA}"
			echo "<tr>" >> .$$.suspicious_request.html
			echo "<td>${SCORE}</td>" >> .$$.suspicious_request.html
			echo "<td>${SCORE_DETAILS}</td>" >> .$$.suspicious_request.html
			echo "<td>${METADATA}</td>" >> .$$.suspicious_request.html
			echo "</tr>" >> .$$.suspicious_request.html
		fi
	done
	echo 
	echo done!
}

view_exposed_key()
{
	echo ""
	highlight ">>> Viewing result of exposed key check" 
	aws --region us-east-1 support describe-trusted-advisor-check-result --check-id 12Fnkpl8Y5 --query 'result.sort_by(flaggedResources[?status!=`ok`],&metadata[2])[].metadata' --output table | tee -a .$$.exposed_key
}

check_exposed_key()
{
	echo ""
	highlight ">>> Refreshing exposed key check"
	aws --region us-east-1 support refresh-trusted-advisor-check --check-id 12Fnkpl8Y5 --query 'status.status'
}

email_report()
{
	echo ""
	highlight ">>> Sending report"
	# For suspicious call
	if [ -f .$$.suspicious_request.html ]; then
		sed -i '1s/^/\<\/tr\>/' .$$.suspicious_request.html
		sed -i '1s/^/\<th\>Request\<\/th\>/' .$$.suspicious_request.html
		sed -i '1s/^/\<th\>Reason\<\/th\>/' .$$.suspicious_request.html
		sed -i '1s/^/\<th\>Score\<\/th\>/' .$$.suspicious_request.html
		sed -i '1s/^/\<tr\>/' .$$.suspicious_request.html
		sed -i '1s/^/\<table style="width:100%"\>/' .$$.suspicious_request.html
		sed -i '1s/^/\<body\>/' .$$.suspicious_request.html
		sed -i '1s/^/\<\/head\>/' .$$.suspicious_request.html
		sed -i '1s/^/\<\/style\>/' .$$.suspicious_request.html
		sed -i '1s/^/}/' .$$.suspicious_request.html
		sed -i '1s/^/border-collapse: collapse;/' .$$.suspicious_request.html
		sed -i '1s/^/border: 1px solid black;/' .$$.suspicious_request.html
		sed -i '1s/^/{/' .$$.suspicious_request.html
		sed -i '1s/^/table, th, td /' .$$.suspicious_request.html
		sed -i '1s/^/\<style\>/' .$$.suspicious_request.html
		sed -i '1s/^/\<head\>/' .$$.suspicious_request.html
		sed -i '1s/^/\<html\>/' .$$.suspicious_request.html
		sed -i '1s/^/\<!DOCTYPE html\>/' .$$.suspicious_request.html
		sed -i '$a\<\/table>' .$$.suspicious_request.html
		sed -i '$a\<\/body>' .$$.suspicious_request.html
		sed -i '$a\<\/html>' .$$.suspicious_request.html
		mail -s "$(echo -e "[keyWatcher] Suspicious AWS API calls\nContent-Type: text/html")" $RECIPIENT < .$$.suspicious_request.html
	else
		echo "No suspicious requests!"
	fi

	# For exposed key
	if [ -s .$$.exposed_key ] ; then
		mail -s "[keyWatcher] Exposed keys are found!" $RECIPIENT < .$$.exposed_key
	else
		echo "No exposed key!"
	fi
}

# User input
ACTION=$1
KEY=$3

# Sumo search timeout (Timeout * 10 seconds )
TIMEOUT=360
# Email suspicious api call list to
RECIPIENT="name@yourdomain.com"

# Options
case $ACTION in
	update_profile)
		RANGE=${2:-"1 day ago"}
		check_dep
		check_connection
		sumo_search "$RANGE" "$KEY"
		extract_output
		update_profile
		;;
	show_profile)
		check_dep
		show_profile $KEY
		;;
	export_profile)
		check_dep
		export_profile
		;;		
	import_profile)
		check_dep
		import_profile
		;;		
	delete_profile)
		check_dep
		delete_profile
		;;
	score_request)
		RANGE=${2:-"10 min ago"}
		check_dep
		check_profile
		check_connection
		sumo_search "$RANGE" "$KEY"
		extract_output
		score_request
		email_report
		;;
	view_exposed_key)
		view_exposed_key
		email_report
		;;
	check_exposed_key)
		check_exposed_key
		;;
	house_keeping)
		house_keeping
		;;
	*)
		usage
		;;
esac

echo ""




