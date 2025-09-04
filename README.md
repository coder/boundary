# Prerequisites

Install tinyproxy: `sudo apt install tinyprox`

Run tinyproxy: `sudo tinyproxy -d`

If you encounter such error:
`touch: cannot touch '/var/log/tinyproxy/tinyproxy.log': Permission denied`

Run:
```
sudo touch /var/log/tinyproxy/tinyproxy.log
sudo chown tinyproxy:tinyproxy /var/log/tinyproxy/tinyproxy.log
sudo chmod 644 /var/log/tinyproxy/tinyproxy.log
```

Allow outgoing traffic in config (comment out all allow directives):
```
# Allow: Customization of authorization controls. If there are any
# access control keywords then the default action is to DENY. Otherwise,
# the default action is ALLOW.
#
# The order of the controls are important. All incoming connections are
# tested against the controls based on order.
#
#Allow 127.0.0.1
#Allow ::1
#Allow 192.168.0.0/16
#Allow 172.16.0.0/12
#Allow 10.0.0.0/8
```

Restart tinyproxy after config is updated.

# Usage
`go build && sudo ./vethpair -- sh`

`curl google.com` - should work