# nx30flash

A small collection of Python tools for working with H3C NX30 routers. It can inspect firmware images, collect information from a router, run upgrade checks, and flash supported routers.

The repository also includes `Final-H3C-N30-L40.bin`, a firmware image, for use with the tools.

## Files

- `nx30flash.py` — interactive terminal menu
- `h3c_probe.py` — local image analysis and read-only router probing
- `h3c_upgrade.py` — upgrade preflight and flashing
- `Final-H3C-N30-L40.bin` — firmware image

## What it does

`nx30flash.py` provides a simple interactive interface for:

- Checking a firmware image before using it
- Reading device model, firmware, memory, storage, boot, and upgrade information
- Testing whether the router is ready for an upgrade
- Flashing one or several routers
- Showing upgrade progress and saving results

The scripts can connect over SSH or Telnet. SSH requires `paramiko`:

```bash
python3 -m pip install paramiko
```

## Why use it

Using the tool before flashing is useful because it checks the image and the router instead of sending firmware blindly. It shows whether the model and image appear to match, whether the required router tools are present, whether there is enough memory and `/tmp` space, and whether the firmware can be downloaded by the router.

For a fleet, `h3c_upgrade.py` can process several routers and save the result of each one to a CSV file.

## Interactive use

Run:

```bash
python3 nx30flash.py
```

The menu lets you analyze an image, probe a router, run a quick preflight check, start an upgrade, or change settings.

## Command-line use

Analyze a firmware image:

```bash
python3 h3c_probe.py --image Final-H3C-N30-L40.bin
```

Read router information without changing it:

```bash
python3 h3c_probe.py --host 192.168.1.1 --user root
```

The script will ask for the password. It uses SSH or Telnet automatically, or you can choose one explicitly:

```bash
python3 h3c_probe.py --host 192.168.1.1 --protocol ssh
python3 h3c_probe.py --host 192.168.1.1 --protocol telnet
```

Run a preflight check without flashing:

```bash
python3 h3c_upgrade.py --image Final-H3C-N30-L40.bin --host 192.168.1.1 --user root
```

Flash a router:

```bash
python3 h3c_upgrade.py --image Final-H3C-N30-L40.bin --host 192.168.1.1 --user root --go
```

The upgrade command asks for confirmation unless `--yes` is supplied.

You can also provide several routers:

```bash
python3 h3c_upgrade.py --image Final-H3C-N30-L40.bin --hosts-file hosts.txt --user root --go
```

Put one host on each line in `hosts.txt`. Lines after `#` are ignored.

## Credentials

Usernames and passwords can be passed as arguments, entered when prompted, or stored in a local `.env` file:

```dotenv
H3C_SSH_USER=root
H3C_SSH_PASS=password
H3C_SSH_PORT=99
H3C_SSH_PROTO=auto
```

Keep real credentials out of version control.

## Firmware downloads

By default, `h3c_upgrade.py` starts a temporary HTTP server and gives the router a URL for the firmware file.

To use an existing URL instead:

```bash
python3 h3c_upgrade.py --image Final-H3C-N30-L40.bin --host 192.168.1.1 --url http://192.168.1.10/firmware.bin --go
```

## Results

Probe reports are saved as text files. Upgrade and quick-check runs save CSV files. `upgrade_state.json` records routers that reported a successful upgrade.

Reports can contain router model, firmware, network, and boot information. It is best not to share them publicly without checking the contents.

## Flashing caution

A failed or interrupted firmware upgrade can brick the router. Do not remove power or reboot the device while it is flashing. Confirm the router model and hardware revision, use a compatible firmware image, and keep a recovery option available.
