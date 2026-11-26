# http_rpc
Simple HTTP service to manage PDU outlets on LuckFox Pico Plus for a custom board developed by Auger electronic service.

# Setup

1) copy `http_rpc.py` in `/usr/bin` 
2) copy `S70http_rpc` in `/etc/init.d`

# User management

Add users or change password with:

```
http_rpc.py --set-user <name>
http_rpc.py --del-user <name>

```

Users file:

```/etc/rpc/http_users```

# Usage

```
❯ curl http://172.32.0.93:8080/output/OUT1/on -u admin:admin
{"OUT1": "on"}

❯ curl http://172.32.0.93:8080/output/OUT1/off -u admin:admin
{"OUT1": "off"}

❯ curl http://172.32.0.93:8080/status -u admin:admin
{"outputs": {"OUT1": 0, "OUT2": 0, "OUT3": 0, "OUT4": 0, "OUT5": 0, "OUT6": 0}, "enable": 1, "adc_mode": "internal", "voltages": {"AN0": 1.798, "AN1": 1.798}}
```
