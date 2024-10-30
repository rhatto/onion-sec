# OnionSec

OnionSec is a tool to help you secure your onion service.

This is the library behind https://onionsec.net.

## Usage example

This is a quick usage example assuming a Debian-like system, but which can be
adapted to other environments.

### Installation

Run the commands below after cloning this repository to the `onion-sec` folder:

    sudo apt install python3-pip python3-virtualenv -y
    mkdir -p ~/.local/share/onion-sec
    virtualenv ~/.local/share/onion-sec/venv
    source ~/.local/share/onion-sec/venv/bin/activate
    cd onion-sec
    pip install .

### Custom Tor daemon

Let's test OnionSec with a custom Tor daemon instance.

Start by installing the tor package:

    sudo apt install tor -y

Create a custom data directory:

    mkdir -p ~/.local/share/onion-sec/tor

Then run the following:

    tor --RunAsDaemon 1 --SocksPort 9052 --ControlPort 9053 \
        --CookieAuthentication 1 --DataDirectory ~/.local/share/onion-sec/tor

Ports `9052` and `9052` are selected to not conflict with the default Tor ports
(`9050` and `9051`).

If you don't want this daemon to fork to the background, run with `--RunAsDaemon 0`
in a separate shell session.

Don't forget to wait a little to make sure the Tor daemon instance is up and
running:

    sleep 20

### Running

Now test OnionSec:

    onion-sec --proxy_port 9052 --control_port 9053 2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion
    INFO:onionsec:Fetching descriptor for 2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid
    DEBUG:stem:GETCONF __owningcontrollerprocess (runtime: 0.0003)
    DEBUG:stem:GETINFO version (runtime: 0.0002)
    INFO:onionsec:Testing HTTP headers for http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion
    INFO:onionsec:Testing Apache mod_status for http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion
    {
      "hidden_service": "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion",
      "open_ports": {
        "http": true,
        "https": false,
        "ssh": false,
        "ftp": false,
        "smtp": false
      },
      "is_single_onion": false,
      "tls_report": null,
      "http_report": {
        "strict_transport_security": null,
        "content_security_policy": {
          "value": "default-src 'self'; script-src 'self' 'sha256-J/tux0AP4WAYsCxprPoE+2XJ+XNJ8Esd8nCF8o/diiw='; style-src 'self' 'unsafe-inline';",
          "secure": false
        },
        "permissions_policy": null,
        "x_frame_options": {
          "value": "SAMEORIGIN",
          "secure": true
        },
        "x_content_type_options": {
          "value": "nosniff",
          "secure": true
        },
        "referer_policy": null,
        "cookies": [],
        "cross_origin_embedder_policy": null,
        "cross_origin_opener_policy": null,
        "cross_origin_resource_policy": null,
        "onion_location": null
      },
      "apache_mod_status_report": {
        "server_info": false,
        "server_status": false
      }
    }
