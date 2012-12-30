#!/bin/sh

WIRELESS_CONFIG_FILE="/etc/config/wireless"

echo $WIRELESS_CONFIG_FILE                 

if [[ $1 = "up" ]]; then  
	sed -i '8s/1/0/' $WIRELESS_CONFIG_FILE
	wifi up
elif [[ $1 = "down" ]]; then
	sed -i '8s/0/1/' $WIRELESS_CONFIG_FILE
	wifi down                             
fi           

