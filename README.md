# http_rpc
Simple HTTP service to manage PDU outlets

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
