
# PSTAT

`PSTAT` is a process monitoring tool designed to monitor the TCP and UDP connections initiated by unknown processes on a system. It provides a comprehensive view of network activities, conducts WHOIS lookups for remote IP addresses, and checks the VirusTotal analysis of the associated processes.

![head image](https://github.com/pfuz/pstat/blob/master/static/images/head-image.png)



## Installation

Clone the repository. Create a virutal environment and install all the required dependencies.

```bash
git clone
cd pstat
python -m venv env
.\env\scripts\activate
pip install -r requirements.txt
```
## Usage
Fill all the necessary fields in `config.yaml` file and run the below command to start the application.
```bash
python pstat.py
```
Check `output.json` for detailed output.
```json
{
        "protocol": "tcp",
        "src_ip": "192.XXX.X.XXX:51656",
        "dest_ip": "20.189.173.1:443",
        "status": "ESTABLISHED",
        "pid": 11008,
        "name": "Code.exe",
        "exe_path": "C:\\Users\\pfuz\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
        "hostname": "PFUZ-COMPUTER",
        "timestamp": "2023-11-17 13:43:01.627840",
        "hash": "e29f03f51ec76170e1ed1db6229211b77c5463b989713977e6f12a30839134f6",
        "virustotal_analysis": {
            "harmless": 0,
            "type-unsupported": 6,
            "suspicious": 0,
            "confirmed-timeout": 0,
            "timeout": 0,
            "failure": 0,
            "malicious": 0,
            "undetected": 70
        },
        "whois": {
            "ip": "20.189.173.1",
            "city": "San Jose",
            "region": "California",
            "country": "US",
            "loc": "37.3394,-121.8950",
            "org": "AS8075 Microsoft Corporation",
            "postal": "95103",
            "timezone": "America/Los_Angeles",
            "readme": "https://ipinfo.io/missingauth"
        }
}
```
## Disclaimer
This tool requires admin privileges to run and will prompts you to approve the access.
## OS Requirements

This tool is tested in Windows 11.
## Main Features

- Performs a basic WHOIS lookup for the remote IP.
- Gets the Virustotal results for applications.


## Note
This tool is still in active development and may have some bugs.
## License
Copyright (c) 2023, Venkata Sai Thotapalli All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

- Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
- Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
- Neither the name of Venkata Sai Thotapalli nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.