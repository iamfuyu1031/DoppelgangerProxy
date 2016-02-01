# DoppelgangerProxy
A standalone version to demo the idea of DoppelgangerProxy.

It can transform tcp traffic into NTP/Minecraft protocol.

**Transform tcp into NTP**
```
python udp_server.py

python tcp_udp_forwarder_ntp.py

python tcp_client.py
```

** Tranform tcp into Minecraft **

> python tcp_server.py

> python tcp_forwarder.py

> python tcp_client.py

You can sniff the network traffic with Wireshark on interfact 'lo'.
