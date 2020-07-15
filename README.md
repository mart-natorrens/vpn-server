# vpn-server-install

Scripts to install and manage some types of VPN-servers.
Scripts install/manage/remove server service. **On board or remotely via SSH.**

Usage:

1. Launch master on board


```
./openvpn-install.sh
```

or

```
./wireguard-install.sh
```

Follow the master prompts 

2. Launch the same master remotely

```
./ssh-openvpn-install.sh user@server
```

or

```
./ssh-wireguard-install.sh user@server
