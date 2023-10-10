# NFSplit
## FakeHandshake NFPlugin

## Description

FakeHandshake is an NFPlugin designed to work with NFStream, providing functionality to perform fake TCP handshakes under certain conditions. This plugin can be utilized to analyze and manipulate network flows, particularly focusing on TCP handshakes.

## Status: Under Development 🚧

Please note that FakeHandshake is currently under development. While it is functional, additional features and improvements are planned for future releases. Use it with caution in production environments.

## Quick Start Guide

Prerequisites
Ensure you have nfstream and scapy installed in your Python environment. If not, install them using pip:
```
pip install nfstream scapy
```
## Basic Usage
Here's a quick guide on how to use the FakeHandshake plugin with NFStream:

```python
from nfstream import NFStreamer, plugins

INTERFACE = 'en1' # Specify your network interface

#Initialize and start the NFStreamer with the FakeHandshake plugin
streamer = NFStreamer(source=INTERFACE, udps=[plugins.FakeHandshake(interface=INTERFACE)], statistical_analysis=True)

#Iterate through the flows generated by NFStreamer
for flow in streamer:
  pass # Your flow processing logic here
```

**Note:**
In the current version, the thresholds and handshake type are hardcoded within the plugin. Future versions aim to allow users to define these parameters directly through NFStreamer.

## License

MIT License
