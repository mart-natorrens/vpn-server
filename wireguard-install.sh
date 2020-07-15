#!/bin/bash
#

# Discard stdin. Needed when running from an one-liner which includes a newline
read -N 999999 -t 0.001

# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
	echo 'This installer needs to be run with "bash", not "sh".'
	exit
fi

# Detect OpenVZ 6
if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
	echo "The system is running an old kernel, which is incompatible with this installer."
	exit
fi

# Detect OS
# $os_version variables aren't always in use, but are kept here for convenience
if grep -qs "ubuntu" /etc/os-release; then
	os="ubuntu"
	os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
	group_name="nogroup"
elif [[ -e /etc/debian_version ]]; then
	os="debian"
	os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
	group_name="nogroup"
elif [[ -e /etc/centos-release ]]; then
	os="centos"
	os_version=$(grep -oE '[0-9]+' /etc/centos-release | head -1)
	group_name="nobody"
elif [[ -e /etc/fedora-release ]]; then
	os="fedora"
	os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
	group_name="nobody"
else
	echo "This installer seems to be running on an unsupported distribution.
Supported distributions are Ubuntu, Debian, CentOS, and Fedora."
	exit
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
	echo "Ubuntu 18.04 or higher is required to use this installer.
This version of Ubuntu is too old and unsupported."
	exit
fi

if [[ "$os" == "debian" && "$os_version" -lt 9 ]]; then
	echo "Debian 9 or higher is required to use this installer.
This version of Debian is too old and unsupported."
	exit
fi

if [[ "$os" == "centos" && "$os_version" -lt 8 ]]; then
	echo "CentOS 8 or higher is required to use this installer.
This version of CentOS is too old and unsupported."
	exit
fi

# Detect environments where $PATH does not include the sbin directories
if ! grep -q sbin <<< "$PATH"; then
	echo '$PATH does not include sbin. Try using "su -" instead of "su".'
	exit
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "This installer needs to be run with superuser privileges."
	exit
fi

if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
	echo "The system does not have the TUN device available.
TUN needs to be enabled before running this installer."
	exit
fi

new_client () {
	# Generates the custom wg-client.conf
	{
		cat /etc/wireguard/clients/client-common.txt
		echo "Address = $1"
		echo -n "PrivateKey = "
		cat /etc/wireguard/clients/${client}/.keys/.private_key
	} > ~/"$client".conf

	{
		echo
		echo "#--$client->"
		echo "[Peer]"
		echo -n "PublicKey = "
		cat /etc/wireguard/clients/${client}/.keys/.public_key
		echo -n "AllowedIPs = "
		cat /etc/wireguard/clients/${client}/.v_ip
		echo "#<-$client--"
	} >> /etc/wireguard/wg1.conf

	echo "The client configuration is available in:" ~/"$client.conf"

	if [ -n "$(which qrencode)" ]; then
		read -p "Show $client QR-code configuration for mobile client? [y/N]: " show_qr_code
		until [[ "$show_qr_code" =~ ^[yYnN]*$ ]]; do
			echo "$show_qr_code: invalid selection."
			read -p "Show $client QR-code configuration for mobile client? [y/N]: " show_qr_code
		done
		if [[ "$show_qr_code" =~ ^[yY]$ ]]; then
			qrencode -t ansiutf8 < ~/"$client.conf"

			read -p "Keep  ~/"$client.conf" file? [y/N]: " delet_client_conf_file
			until [[ "$delet_client_conf_file" =~ ^[yYnN]*$ ]]; do
				echo "$delet_client_conf_file: invalid selection."
				read -p "Keep  ~/"$client.conf" file? [y/N]: " delet_client_conf_file
			done

			if [[ "$delet_client_conf_file" =~ ^[nN]$ ]]; then
				dd 	if=/dev/urandom count=1 bs=1024 of=~/"$client.conf" 2>/dev/null
				if [ -n "$(which shred)" ]; then
					shred -fuzn 2 ~/"$client.conf"
				else
	                rm -f $1
				fi
			fi
		fi
	fi
}

if [[ ! -e /etc/wireguard/wg1.conf ]]; then
	clear
	echo 'Welcome to this WireGuard road warrior installer!'
	# If system has a single IPv4, it is selected automatically. Else, ask the user
	if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	else
		number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
		echo
		echo "Which IPv4 address should be used?"
		ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
		read -p "IPv4 address [1]: " ip_number
		until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
			echo "$ip_number: invalid selection."
			read -p "IPv4 address [1]: " ip_number
		done
		[[ -z "$ip_number" ]] && ip_number="1"
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
	fi
	# If $ip is a private IP address, the server must be behind NAT
	if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo
		echo "This server is behind NAT. What is the public IPv4 address or hostname?"
		# Get public IP and sanitize with grep
		get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
		read -p "Public IPv4 address / hostname [$get_public_ip]: " public_ip
		# If the checkip service is unavailable and user didn't provide input, ask again
		until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
			echo "Invalid input."
			read -p "Public IPv4 address / hostname: " public_ip
		done
		[[ -z "$public_ip" ]] && public_ip="$get_public_ip"
	fi
	# If system has a single IPv6, it is selected automatically
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
	fi
	# If system has multiple IPv6, ask the user to select one
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
		number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
		echo
		echo "Which IPv6 address should be used?"
		ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
		read -p "IPv6 address [1]: " ip6_number
		until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
			echo "$ip6_number: invalid selection."
			read -p "IPv6 address [1]: " ip6_number
		done
		[[ -z "$ip6_number" ]] && ip6_number="1"
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
	fi
	echo
	echo "What port should WireGuard listen to?"
	read -p "Port [51820]: " port
	until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
		echo "$port: invalid port."
		read -p "Port [51820]: " port
	done
	[[ -z "$port" ]] && port="51820"
	echo
	echo "Select a DNS server for the clients:"
	echo "   1) Private server DNS (must be installed on 53 port!)"
	echo "   2) Current system (client) resolver (from 127.0.0.53)"
	echo "   3) Google"
	echo "   4) 1.1.1.1"
	echo "   5) OpenDNS"
	echo "   6) Quad9"
	echo "   7) AdGuard"
	read -p "DNS server [2]: " dns
	until [[ -z "$dns" || "$dns" =~ ^[1-7]$ ]]; do
		echo "$dns: invalid selection."
		read -p "DNS server [2]: " dns
	done
	echo
	echo "Enter a name for the first client:"
	read -p "Name [wg-client]: " unsanitized_client
	# Allow a limited set of characters to avoid conflicts
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	[[ -z "$client" ]] && client="wg-client"
	echo
	echo "WireGuard installation is ready to begin."
	read -n1 -r -p "Press any key to continue..."
	# If running inside a container, disable LimitNPROC to prevent conflicts
	if systemd-detect-virt -cq; then
		mkdir /etc/systemd/system/wireguard-server@server.service.d/ 2>/dev/null
		echo "[Service]
LimitNPROC=infinity" > /etc/systemd/system/wireguard-server@server.service.d/disable-limitnproc.conf
	fi
	if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then # Ubuntu ≥ 19.10
		apt-get update
		apt install -y wireguard
		modprobe wireguard 2>/dev/null 1>&2;
		if [ $? -ne 0 ]; then # throuble shutting
			apt install -y wireguard-dkms wireguard-tools linux-headers-$(uname -r)
		fi
		apt install -y qrencode
	elif [[ "$os" = "centos" ]]; then # CentOS 8 (https://www.wireguard.com/install/#centos-8-module-tools)
		yum install -y elrepo-release epel-release
		yum install -y kmod-wireguard wireguard-tools
	else
		# Else, OS must be Fedora
		dnf install -y wireguard-tools
	fi

	clear

	default_vpn_ip_for_server="10.61.12.1/24"
    read -p "Enter the server address in the VPN subnet (CIDR format) [${default_vpn_ip_for_server}]: " vpn_ip_for_server
	until [[ -z "$vpn_ip_for_server" || $vpn_ip_for_server =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; do
		read -p "Enter valid IPv4 [${default_vpn_ip_for_server}]: " vpn_ip_for_server
	done

	if [ -z "$vpn_ip_for_server" ]; then
		vpn_ip_for_server=$default_vpn_ip_for_server
	fi

	# Create config folders and keys
	save_mode=$(umask)
	umask 077
	mkdir -p /etc/wireguard/server/.keys/
	mkdir -p /etc/wireguard/clients/${client}/.keys
	chown -R root:root /etc/wireguard/server/.keys/
	cd /etc/wireguard/server/.keys/
	wg genkey | tee ./.private_key | wg pubkey > ./.public_key
	cd /etc/wireguard/clients/${client}/.keys/
	wg genkey | tee ./.private_key | wg pubkey > ./.public_key
	
	cd /etc/wireguard/server
	echo $vpn_ip_for_server | grep -o -E '([0-9]+\.){3}' > ./vpn_subnet.var
	cd /etc/wireguard/clients
	echo 1 > ./last_used_vpn_ip_index.var

	touch /etc/wireguard/wg1.conf
	touch /etc/wireguard/clients/client-common.txt

	read octet_ip < ./last_used_vpn_ip_index.var
	octet_ip=$(($octet_ip+1))
	echo $octet_ip > ./last_used_vpn_ip_index.var

	read vpn_subnet < /etc/wireguard/server/vpn_subnet.var

	vpn_ip_for_client="${vpn_subnet}${octet_ip}/32"

	echo $vpn_ip_for_client > ./${client}/.v_ip

	umask $save_mode

	default_inet=$(ip route | grep default | sed -e "s/^.*dev.//" -e "s/.proto.*//")

	# Generate server config file
	{
		echo "[Interface]"
		echo "Address = $vpn_ip_for_server"
		echo "PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $default_inet -j MASQUERADE"
		echo "PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $default_inet -j MASQUERADE"
		echo "ListenPort = $port"
		echo -n "PrivateKey = "
		cat /etc/wireguard/server/.keys/.private_key
	} > /etc/wireguard/wg1.conf

	# If the server is behind NAT, use the correct IP address
	[[ -n "$public_ip" ]] && ip="$public_ip"

	# client-common.txt is created so we have a template to add further users later
	{
		echo "[Peer]"
		echo -n "PublicKey = "
		cat /etc/wireguard/server/.keys/.public_key
		echo "Endpoint = $ip:$port"
		echo "AllowedIPs = 0.0.0.0/0"
		echo "PersistentKeepalive = 21"
		echo
		echo "[Interface]"
	} > /etc/wireguard/clients/client-common.txt

	# DNS
	case "$dns" in
		1)
			echo "DNS = $ip" >> /etc/wireguard/clients/client-common.txt
		;;
		2|"")
			echo "DNS = 127.0.0.53" >> /etc/wireguard/clients/client-common.txt
		;;
		3)
			echo 'DNS = 8.8.8.8' >> /etc/wireguard/clients/client-common.txt
			echo 'DNS = 8.8.4.4' >> /etc/wireguard/clients/client-common.txt
		;;
		4)
			echo 'DNS = 1.1.1.1' >> /etc/wireguard/clients/client-common.txt
			echo 'DNS = 1.0.0.1' >> /etc/wireguard/clients/client-common.txt
		;;
		5)
			echo 'DNS = 208.67.222.222' >> /etc/wireguard/clients/client-common.txt
			echo 'DNS = 208.67.220.220' >> /etc/wireguard/clients/client-common.txt
		;;
		6)
			echo 'DNS = 9.9.9.9' >> /etc/wireguard/clients/client-common.txt
			echo 'DNS = 149.112.112.112' >> /etc/wireguard/clients/client-common.txt
		;;
		7)
			echo 'DNS = 176.103.130.130' >> /etc/wireguard/clients/client-common.txt
			echo 'DNS = 176.103.130.131' >> /etc/wireguard/clients/client-common.txt
		;;
	esac

	# Enable net.ipv4.ip_forward for the system
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/30-wireguard-forward.conf
	# Enable without waiting for a reboot or service restart
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if [[ -n "$ip6" ]]; then
		# Enable net.ipv6.conf.all.forwarding for the system
		echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/30-wireguard-forward.conf
		# Enable without waiting for a reboot or service restart
		echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
	fi
	# If SELinux is enabled and a custom port was selected, we need this
	if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 51820 ]]; then
		# Install semanage if not already present
		if ! hash semanage 2>/dev/null; then
			if [[ "$os_version" -eq 7 ]]; then
				# Centos 7
				yum install -y policycoreutils-python
			else
				# CentOS 8 or Fedora
				dnf install -y policycoreutils-python-utils
			fi
		fi
		semanage port -a -t wireguard_port_t -p "udp" "$port"
	fi

	# Generates the custom client config
	new_client $vpn_ip_for_client

	# Enable and start the WireGuard service
	systemctl enable --now wg-quick@wg1.service #>/dev/null 2>&1

	echo
	echo "Finished!"
	echo

	echo "New clients can be added by running this script again."
else
	clear
	echo "WireGuard is already installed."
	echo
	echo "Select an option:"
	echo "   1) Add a new client"
	echo "   2) Revoke an existing client"
	echo "   3) Remove WireGuard"
	echo "   4) Exit"
	read -p "Option: " option
	until [[ "$option" =~ ^[1-4]$ ]]; do
		echo "$option: invalid selection."
		read -p "Option: " option
	done
	case "$option" in
		1)
			echo
			echo "Provide a name for the client:"
			read -p "Name: " unsanitized_client
			client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
			while [[ -z "$client" || -e /etc/wireguard/clients//${client}/.private_key || -e /etc/wireguard/clients/keys/${client}/.public_key ]]; do
				echo "$client: invalid name."
				read -p "Name: " unsanitized_client
				client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
			done

			save_mode=$(umask)
			umask 077
			mkdir -p /etc/wireguard/clients/${client}/.keys
			cd /etc/wireguard/clients/${client}/.keys
			wg genkey | tee ./.private_key | wg pubkey > ./.public_key
			cd /etc/wireguard/clients

			read octet_ip < ./last_used_vpn_ip_index.var
			octet_ip=$(($octet_ip+1))
			if (( $octet_ip > 254 )); then octet_ip=2; fi
			echo $octet_ip > ./last_used_vpn_ip_index.var

			read vpn_subnet < /etc/wireguard/server/vpn_subnet.var

			vpn_ip_for_client="${vpn_subnet}${octet_ip}"

			read -p "Submit new client virtual IP address [${vpn_ip_for_client}]: " vpn_ip_for_server_
			until [[ -z "$vpn_ip_for_server_" || $vpn_ip_for_server_ =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; do
				read -p "Submit new client virtual IP address [${vpn_ip_for_client}]: " vpn_ip_for_server_
			done

			if [ -n "$vpn_ip_for_server_" ]; then
				vpn_ip_for_server=vpn_ip_for_client_
			fi

			vpn_ip_for_client="${vpn_ip_for_client}/32"

			echo $vpn_ip_for_client > ./${client}/.v_ip

			umask $save_mode

			# Generates the custom client config
			new_client $vpn_ip_for_client
			
			systemctl restart wg-quick@wg1

			exit
		;;
		2)
			# This option could be documented a bit better and maybe even be simplified
			# ...but what can I say, I want some sleep too
			number_of_clients=$(find /etc/wireguard/clients -maxdepth 1 -type d -not -path '.' 2>/dev/null|wc -l)
			if [[ "$number_of_clients" = 0 ]]; then
				echo
				echo "There are no existing clients!"
				exit
			fi
			echo
			echo "Select the client to revoke:"
			cd /etc/wireguard/clients
			find . -maxdepth 1 -type d -not -path '.' 2>/dev/null|cut -d '/' -f 2|awk '{print "   "NR")",$0}'
			read -p "Client: " client_number
			until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
				echo "$client_number: invalid selection."
				read -p "Client: " client_number
			done
			client=$(find . -maxdepth 1 -type d -not -path '.' 2>/dev/null|cut -d '/' -f 2|sed -n "$client_number"p)
			echo
			read -p "Confirm $client revocation? [y/N]: " revoke
			until [[ "$revoke" =~ ^[yYnN]*$ ]]; do
				echo "$revoke: invalid selection."
				read -p "Confirm $client revocation? [y/N]: " revoke
			done
			if [[ "$revoke" =~ ^[yY]$ ]]; then
				conf_changed=
				start_conf=$(grep -n -r "<-${client}-" /etc/wireguard/wg1.conf|cut -d ':' -f 1)
				end_conf=$(grep "\-${client}->" /etc/wireguard/wg1.conf|cut -d ':' -f 1)
				if [[ -n $start_conf && -n $end_conf ]]; then
					start_conf=$(($start_conf-1))
					cat /etc/wireguard/wg1.conf|awk "\"NR < $start_conf || NR > $end_conf { print }\"" > /etc/wireguard/wg1.conf
					conf_changed=1
				fi

				rm -rf /etc/wireguard/clients/$client
				
				if [ -n $conf_changed ]; then
					systemctl restart wg-quick@wg1
				fi

				echo
				echo "$client revoked!"
			else
				echo
				echo "$client revocation aborted!"
			fi
			exit
		;;
		3)
			echo
			read -p "Confirm WireGuard removal? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: invalid selection."
				read -p "Confirm WireGuard removal? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				port=$(grep '^ListenPort ' /etc/wireguard/wg1.conf | cut -d " " -f 3)
				if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 51820 ]]; then
					semanage port -d -t wireguard_port_t -p "udp" "$port"
				fi
				systemctl disable --now wg-quick@wg1.service
				rm -rf /etc/wireguard
				rm -f /etc/systemd/system/wireguard-server@server.service.d/disable-limitnproc.conf
				rm -f /etc/sysctl.d/30-wireguard-forward.conf
				if [[ "$os" = "debian" || "$os" = "ubuntu" ]]; then
					apt-get remove --purge -y wireguard
				else
					# Else, OS must be CentOS or Fedora
					yum remove -y wireguard-tools
				fi
				echo
				echo "WireGuard removed!"
			else
				echo
				echo "WireGuard removal aborted!"
			fi
			exit
		;;
		4)
			exit
		;;
	esac
fi
