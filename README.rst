python-vpn
============

|made-with-python| |PyPI-version| |Hit-Count|

.. |made-with-python| image:: https://img.shields.io/badge/Made%20with-Python-1f425f.svg
   :target: https://www.python.org/
.. |PyPI-version| image:: https://badge.fury.io/py/pvpn.svg
   :target: https://pypi.python.org/pypi/pvpn/
.. |Hit-Count| image:: http://hits.dwyl.io/qwj/python-vpn.svg
   :target: https://pypi.python.org/pypi/pvpn/

IPSec IKE(v1,v2) PSK VPN implemented in pure Python. **(For Research Purposes Only)**

Introduction
------------

All VPN softwares are stupid, clumsy and hard to configure. So comes **python-vpn**. 

- NO app install needed
- NO server configuration file
- NO network interface added
- NO iptables or "/etc" modified

Press "RETURN" to start, "CTRL+C" to stop.

QuickStart
----------

.. code:: rst

  $ pip3 install pvpn
  Successfully installed pvpn-0.1.2
  $ pvpn -p yourpassword
  Serving on UDP :500 :4500...
  ^C

Open server's UDP port :500 :4500 to your device. In device's system setting, add an "IPSec" (iOS) or "IPSec IKE PSK" (Android) VPN, write down the server address and password "yourpassword". Connect.

You should change the default password "test" to keep higher security. See "pvpn -h" for more options.

Features
--------

- Clean, lightweight and easy to use
- IKEv1, IKEv2 auto-detection
- TCP stack implementation
- TCP/UDP tunnel support

Protocols
---------

+-------------------+----------------+-------------------+
| Name              | Name in iOS    | Name in Android   |
+===================+================+===================+
| IKEv1 PSK ✔       | IPsec **[1]**  | "IPSec Xauth PSK" |
+-------------------+----------------+-------------------+
| IKEv2 PSK ✔       | IKEv2 **[2]**  | "IPSec IKEv2 PSK" |
+-------------------+----------------+-------------------+

| **[1]** Do not use certificates
| **[2]** Turn off "user authentication"

Examples
--------

You can tunnel traffic to remote http/socks/ss proxy as follows:

.. code:: rst

  $ pvpn -r http://12.34.56.78:8080/
  # Tunnel all TCP traffic to remote HTTP proxy

  $ pvpn -r ss://chacha20:abc@12.34.56.78:12345/
  # Tunnel all TCP traffic to remote Shadowsocks proxy

  $ pvpn -ur ss://aes-256-cfb:abc@12.34.56.78:23456/
  # Tunnel all UDP traffic to remote Shadowsocks proxy

  $ pvpn -r socks5://12.34.56.78:8123/?rules.regex
  # Tunnel TCP traffic matched by rules.regex to remote HTTP proxy

  $ pvpn -r ss:///tmp/local
  # Tunnel TCP traffic to unix domain path /tmp/local


