#! /bin/bash
function is_bridge_exist()
{
    brname="$1"
    if [ -e "/sys/class/net/$brname" ];
    then
	    return 0;
    fi;

    return 1;
}

function create_bridge()
{
    brname="$1"
    brctl addbr "$brname"
}

function delete_bridge()
{
    brname="$1"
    brctl delbr "$brname"
}

function setup_bridge()
{
    brname="$1"
    br_address="$2"
    broadcast="$3"

    if is_bridge_exist "$brname" ;
    then
	echo "br0 exist";
    else
	echo "br0 not exist";
	create_bridge "$brname"
    fi;

    ip link set "$brname" up;
    ip address flush dev "$brname"
    ip address add "$br_address" broadcast "$broadcast" dev "$brname" 
}

function setup_natconfig()
{
	private_inf="$1"
	public_inf="$2"
	echo 1 > /proc/sys/net/ipv4/ip_forward
	iptables -t nat -A POSTROUTING -o "$public_inf" -j MASQUERADE
	iptables -A FORWARD -i "$public_inf" -o "$private_inf" -m state --state RELATED,ESTABLISHED -j ACCEPT
	iptables -A FORWARD -i "$private_inf" -o "$public_inf" -j ACCEPT
}

function setup_dnsmasq()
{
	brname="$1"
	cat << EOF > /etc/dnsmasq.d/hostap_dnsmasq.conf
	interface=$brname
	dhcp-range=10.10.11.100,10.10.11.200,255.255.255.0,12h
	dhcp-option=3,10.10.11.1
	dhcp-option=6,114.114.114.114
EOF

	systemctl restart dnsmasq
}


if [ ! `id -u` -eq 0 ];
then
	echo "require root login"
	exit 1
fi;

setup_bridge "br0" "10.10.11.1/24" "10.10.11.255"
#add nat config
setup_natconfig "br0" "eth0"
setup_dnsmasq "br0"

./hostapd/hostapd ./hostapd/anlang_hostapd.conf 
