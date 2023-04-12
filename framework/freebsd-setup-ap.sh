#!/bin/sh
# Copyright (C) 2021-2023 Domien Schepers.

if [ $# -eq 0 ] ; then
    echo "Usage; $0 interface"
    exit 1
fi

# Parameters.
IFACE=$1
SSID="testnetwork"
CHANNEL="1"
IP="192.168.0.1"
NETMASK="255.255.255.0"
DHCP=true
HOSTAPD=true
HOSTAPD_CONFIG="./hostapd.conf"
HOSTAPD_DEBUG=false

# Configure the interface.
ifconfig wlan0 destroy
ifconfig wlan0 create wlandev $IFACE wlanmode hostap
ifconfig wlan0 ssid $SSID mode 11g channel $CHANNEL
ifconfig wlan0 inet $IP netmask $NETMASK
ifconfig wlan0

# Load kernel module e.g. enabling CCMP-support in hostap.
kldload -n wlan_xauth

# Optionally enable the DHCP service.
# Configured in /usr/local/etc/dhcpd.conf.
if [ "$DHCP" = true ] ; then
    service isc-dhcpd stop
    service isc-dhcpd start
fi

# Optionally start hostapd.
if [ "$HOSTAPD" = true ] ; then
	if [ "$HOSTAPD_DEBUG" = false ] ; then
		hostapd -i wlan0 $HOSTAPD_CONFIG
	else
		hostapd -i wlan0 -dd -K $HOSTAPD_CONFIG
	fi
fi
