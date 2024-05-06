RDP is based on, and is an extension of, the T-120 family of protocol standards. A multichannel capable protocol allows for separate virtual channels for carrying the following information:

- presentation data
- serial device communication
- licensing information
- highly encrypted data, such as keyboard, mouse activity

RDP is an extension of the core T.Share protocol. Several other capabilities are retained as part of the RDP, such as the architectural features necessary to support multipoint (multiparty sessions). Multipoint data delivery allows data from an application to be delivered in **real time** to multiple parties, such as Virtual Whiteboards. It doesn't require to send the same data to each session individually
# Useful Commands:

 we can use this command to remotely connect to a server using the command line:
 
```cmd
cmdkey /generic:"server-address" /user:"username" /pass:"password"
mstsc /v:server-address
cmdkey /delete:server-address
```