python-vpn
============

|made-with-python| |PyPI-version| |Hit-Count|

.. |made-with-python| image:: https://img.shields.io/badge/Made%20with-Python-1f425f.svg
   :target: https://www.python.org/
.. |PyPI-version| image:: https://badge.fury.io/py/pvpn.svg
   :target: https://pypi.python.org/pypi/pvpn/
.. |Hit-Count| image:: http://hits.dwyl.io/qwj/python-vpn.svg
   :target: https://pypi.python.org/pypi/pvpn/

IKE(v1,v2) PSK+ESP(UDP) VPN implemented in pure Python.

Introduction
------------

All VPN softwares are stupid, clumsy and hard to config. So comes **python-vpn**.

QuickStart
----------

.. code:: rst

  $ pip3 install pvpn
  Successfully installed pvpn-0.0.5
  $ pvpn -p yourpassword
  Serving on UDP :500 :4500...
  ^C

Open the UDP port :500 :4500 to your device. Add "IKEv2 (iOS) (Turn off User Authentication)" or "IPSec IKEv2 PSK (Android)" VPN, write down the id "test" and password "yourpassword". Connect.

You should change the default password to keep higher security. See "pvpn -h" for more options.

Features
--------

- IKEv1, IKEv2 PSK support, auto-detect
- TCP stack implementation
- Tunnel tcp/udp to your proxy

Protocols
---------

+-------------------+----------------+-------------------+
| Name              | iOS            | Android           |
+===================+================+===================+
| IKEv1 PSK ✔       | IPsec          | "IPSec Xauth PSK" |
+-------------------+----------------+-------------------+
| IKEv2 PSK ✔       | IKEv2          | "IPSec IKEv2 PSK" |
+-------------------+----------------+-------------------+
