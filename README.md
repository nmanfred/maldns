# Setup

Install `tshark`, `python3`, and `pip3`. Then:

```
git clone git@github.com:nmanfred/maldns.git
cd maldns/
git submodule init
git submodule update
pip3 install -r requirements.txt
```

Obtain a VirusTotal API key and paste into file named `vtapikey` in the `maldns` directory

# Running

python3 main.py # Note: tshark may require sudo/admin privileges depending on your system configuration

# Using


# Notes

* You may want to clear your cache before running in case it already contains suspicious entries.
Search for instructions for how to do this on your operating system (e.g. [Linux](https://beebom.com/how-flush-dns-cache-linux/),[MacOS and Windows 10](https://phoenixnap.com/kb/how-to-flush-dns-cache))

* VirusTotal *private access* users can scan domains more frequently. Set this option in config.py.

* Without private access, you may generate more entries than can be looked up on VirusTotal. You can add entries to lists/whitelist and lists/blacklist to avoid querying for known sites. Browser extensions such as uBlock Origin, Privacy Badger, and Ghostery can help block trackers and reduce the number of VirusTotal queries.
