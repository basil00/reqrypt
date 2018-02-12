# REQRYPT

ReQrypt is a tool for tunneling and encrypting web browser requests to hide
them from local (e.g. router-level, or ISP-level) snooping and interception.
ReQrypt is useful for bypassing ISP-level URL censorship/filtering/logging
systems.

ReQrypt works very differently than other bypassing methods.  ReQrypt is based
on a technology known as "triangular routing".  In a nutshell, ReQrypt works
like this:


    (1) Tunneled request      +----------------+      (2) Forwarded request
               +------------->| ReQrypt server |-------------+
               |              +----------------+             |
               |                                             |
               |                                             V
       +----------------+                             +----------------+
       | PC web browser |<----------------------------|   Web server   |
       +----------------+                             +----------------+
                            (3) Web-page response

Basically:

1. Your web browser issues a HTTP request to the web-server, which is
   encrypted and tunnelled to a ReQrypt server.
2. The ReQrypt server decrypts the tunneled packet, and forwards it to the
   web-server.
3. The web-server responds the HTTP request as if it came directly from your
   computer, and the web page response is sent back via the normal route.

Ordinarily, the HTTP request is sent directly to the web server, unencrypted.
This means it may be read and/or intercepted by a local eavesdropper, such as
your ISP, workplace, or shared family router.  However, with ReQrypt the
outgoing HTTP requests are encrypted and tunneled, rendering them unreadable
to any local eavesdropper.

ReQrypt is effective against systems that only attack outbound HTTP requests
only, and ignore inbound HTTP responses.  Such systems are very common is
ISP-level censorship and logging systems, since processing URL traffic (HTTP
requests) is significantly easier than processing web page responses.

Finally, unlike proxies, VPNs, Tor, etc., ReQrypt is not an anonymity tool.
It does not change the IP address of the tunneled packet.  This can be a good
thing: it means the web responses are sent directly to your PC which means
ReQrypt is typically faster than these other systems.

# LICENSE

This package is distributed under the GNU Public License (GPL) Version 3.

Please note the following:

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see http://www.gnu.org/licenses/

# COPYRIGHT

(C) 2018, basil00, all rights reserved.

