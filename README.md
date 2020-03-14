# IOT-Defender
## Overview
 IOT is one of the largest growing industries right now and with that comes a lot of growing pains. One of the main concerns with IOT devices currently is their security. To help address this we decided to not only build something that could monitor these devices but also actively block traffic. This wireless access point running on a raspberry pi is not only capable of doing just that but also is extremely pluggable and easily modifiable.
## Setup
This guide is really useful to setting up a rasperry pi to be a wireless access point - https://pimylifeup.com/raspberry-pi-wireless-access-point/. 
After going through that setup in its entirety, add these three iptable firewall rules.
```
  sudo iptables -A INPUT -i eth0 -p tcp --dport 22 -j ACCEPT # Allow ssh for yourself if needed
  sudo iptables -A INPUT -i wlan0 -j NFQUEUE --queue-num 1
  sudo iptables -A FORWARD -i wlan0 -j NFQUEUE --queue-num 1
```
At this point the access point should be broadcasting and discoverable but after connecting you will not be able to connect to the internet just yet. We now need to start the python daemon for packet-filter.py to start it listening and accepting (or denying) packets.
``` 
sudo python packet-filter.py
```
Now all connected devices should be able to reach the internet and any log statements should print to the screen.
## Additions
This project was made with the goal of being extremely extendable and pluggable. Any new firewall rules can be added by including them in the ```filter(packet)``` function. An example has been provided in the packet-filter.py code.
