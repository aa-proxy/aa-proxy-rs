# 🛸 aa-proxy-rs

## About
This is a Rust-Written proxy tool to bridge between wireless android phone and a USB-wired car head unit for using Google's Android Auto.
Currently it is intended to run as a more-or-less drop-in replacement of the `aawgd` from the [WirelessAndroidAutoDongle](https://github.com/nisargjhaveri/WirelessAndroidAutoDongle) project.

## History and motivation
There are a lot of commercial solutions like AAWireless or Motorola MA1. I even bought a clone of those on AliExpress, but it ended up not working in my car (passed to my friend which has a compatible car for this).

Then thanks to [Nicnl](https://www.reddit.com/user/Nicnl/) from reddit under my [post](https://www.reddit.com/r/RenaultZoe/comments/1c5eg2g/working_wireless_aa_for_rlink1_based_zoe/),
I headed to a great open source solution, based on Raspberry Pi hardware:<br>
[WirelessAndroidAutoDongle](https://github.com/nisargjhaveri/WirelessAndroidAutoDongle) by [Nisarg Jhaveri](https://github.com/nisargjhaveri)

The author made a lot of great research and created a DIY working solution, and - what is most important - he shared his work to the public.
This is so cool and I really appreciate his work!
Because it's open source, I was even able to run my own additional LoRa hardware on the same Raspberry Pi for different purpose!

The original project is using `aawgd` daemon which is doing the necessary proxying of data between the phone and USB port.
(Un)fortunately the project was not always working reliable for me (crashing, unable to reconnect, need restarting, etc.).
Finally after making this [PR](https://github.com/nisargjhaveri/WirelessAndroidAutoDongle/pull/196), I decided that I will try to make the Rust-based alternative.
And this is where this project begins and I started to reimplement the `aawgd` C++ code into rust application.

## Coding
I was trying to simplify things and original code where it was possible.
It was also a great opportunity and fun to learn how it was designed and how it is working, but I have to admit that I was struggling a lot with doing a final forwarding I/O:
normally I would just use [copy_bidirectional](https://docs.rs/tokio/latest/tokio/io/fn.copy_bidirectional.html) for this as the whole code is async and using [tokio](https://tokio.rs/), but
the problem with it was, that the USB socket for the "usb-gadget" kernel module seems to be not compatible with this approach (probably some polling/epoll problems).
I was also trying to call read/writes in tokio tasks, but finally I decided to use different approach: using modern [io_uring](https://kernel.dk/io_uring.pdf) kernel API provided by [tokio_uring](https://github.com/tokio-rs/tokio-uring).
And this finally worked perfectly fine (and also really efficient as a bonus).

## Limitations
Currently only the default "connection strategy" is supported. I don't have a clue if and when I add the other ones. Time will tell.
My time resources are limited, so don't expect to prompt answers and ETAs on different requests. I am doing this as a hobby in my spare time.
I've tested this only with my own `Raspberry Pi Zero 2 W` and my specific car head unit (old Renault R-Link).
Config parameters from `/etc/aawgd.env` are not (yet?) supported.

## Current stage and plans
This project is on early stage of development:
~~The tool is currently working fine for me from Raspberry Pi boot up to initial phone connection. It is then working stable until the phone goes out of range.
There is left a lot of work to make it more stable and reliable, especially I am planning to add reconnecting/recovering code where it is applicable.~~<br>
UPDATE: reconnecting code is now in place and working quite nice! :)

## How it works (technical)
![Hardware overview](images/aa-proxy-rs.webp)
The whole connection process is not trivial and quite complex. Here I am listing the needed steps the app is doing from the start to make a connection:
- USB: disabling all gadgets
- USB: registering uevents (for receiving USB state changes)
- Starting local TCP server
- Bluetooth: powering up the bluetooth adapter and make it discoverable and pairable
- Bluetooth: registering two profiles: one for android auto, and the other for fake headset (fooling the phone we are supported wireless AndroidAuto head unit)
- When a phone connects to the AA profile the app is sending two frames of specific google protocol data:
  - WifiStartRequest: with IP address and port of the destination TCP server/connection
  - WifiInfoResponse: with Access Point information for the WiFi connection
- after successfull response for the above, the tool is disabling bluetooth
- the phone is connecting to car's head unit bluetooth (e.g. for phone calls)
- in the same time the phone is connecting via WiFi to our TCP server on specified port
- USB: switching to "default" followed by "accessory" gadgets to enable proper USB mode for data transmission to the car head unit (fooling that we are the android phone connected via USB)
- final (and normal working stage): bidirectional forwarding the data between TCP client (phone) and USB port (car)

USB is the active part here (starting the transmission by sending 10-bytes first frame), so all of this has to be done with well timing, i.e., if we start the USB dongle connection too fast
(when the phone is not yet connected), then it would start the transmission, and we don't have a TCP socket ready; similar in the other direction: when the phone starts too fast, and we are
not ready with USB connection then we can't send data to the phone and Android will close/timeout the connection.

## Demo
[![asciicast](https://asciinema.org/a/686949.svg)](https://asciinema.org/a/686949)

## Building and installing
`rpi02w` binaries build by [WirelessAndroidAutoDongle](https://github.com/nisargjhaveri/WirelessAndroidAutoDongle) are for `arm-unknown-linux-gnueabihf` 32-bit architecture, probably
because of usb-gadget module [incompatibility](https://github.com/nisargjhaveri/WirelessAndroidAutoDongle/pull/129).
To be able to properly crosscompile output binary I provided `.cargo/config.toml` with target set for this specific arch.

To compile you need to add proper rustup target with:
```
rustup target add arm-unknown-linux-gnueabi
```
and make sure that it is _installed_ on target list:
```
arm-unknown-linux-gnueabihf (installed)
```
Besides a `gcc-arm-linux-gnueabihf` package is needed on Debian. This is distro-depended so I recommend to RTFM.

After building you need to transfer the binary to the target filesystem (I am using ssh/scp for this) and start it.
For permanent solution I also modified startup scripts - but how to do it is out of scope of this document.

## Building using Docker
To build with Docker you need to have a [buildx](https://github.com/docker/buildx) and [BuildKit](https://github.com/moby/buildkit).<br>
Then you can e.g. create some output dir and build the binary like this:
```
mkdir out
DOCKER_BUILDKIT=1 docker build --output out .
```
After successful execution the resulting `aa-proxy-rs` will be in `out` directory.

## Usage
```
aa-proxy-rs 0.1.0
AndroidAuto wired/wireless proxy

USAGE:
    aa-proxy-rs [OPTIONS]

OPTIONS:
    -a, --advertise                   BLE advertising
    -c, --connect <CONNECT>           Auto-connect to saved phone or specified phone MAC address if
                                      provided
    -d, --debug                       Enable debug info
    -l, --legacy                      Enable legacy mode
    -h, --help                        Print help information
    -l, --logfile <LOGFILE>           Log file path [default: /var/log/aa-proxy-rs.log]
    -s, --stats-interval <SECONDS>    Interval of showing data transfer statistics (0 = disabled)
                                      [default: 0]
    -V, --version                     Print version information
```
Most options are self explanatory, but these needs some more attention:<br>
- `-l, --legacy`<br>
Original `aawgd` is using two USB gadgets: **default** and **accessory**. When connecting to car headunit, it switches first to **default** then to **accessory**.
During my development I found out that my car headunit doesn't need this switching. It is working fine connecting directly to **accessory** gadget.
Moreover with this approach it is much faster and doesn't need to wait for USB events in dedicated _UEvent_ thread. As the result I decided to leave the old (legacy)
code under this switch for compatibility with some headunits.<br>
In short: if you have problems with USB connection try to enable the legacy mode.

- `-c, --connect <CONNECT>`<br>
By default without this switch the aa-proxy-rs is starting but it is only visible as a bluetooth dongle, to which you have to connect manually from your phone to
initiate AndroidAuto connection. If I am correct this was called `dongle mode` in `aawgd`.<br>
If you provide `-c` switch without any additional address, then the daemon is trying to connect to known (paired?) bluetooth devices (phones) in a loop
(the **bluetoothd** have a cached list of recently connected devices in /var/lib/bluetooth). This is the default mode for `aawgd` for the time I am writing this.<br>
If you provide `-c MAC_ADDRESS` where MAC_ADDRESS is the MAC of your phone (bluetooth), then the aa-proxy-rs will try to connect only to this specified device
in a loop (ignoring all **bluetoothd** cached devices).

## Steps to Follow To Auto Start Script
1. SSH into the RPi
2. Delete `aawgd` from `usr/bin`
3. Add `aa-proxy-rs` to `usr/bin`
4. Rename `aa-proxy-rs` to `aawgd`
5. Run `chmod +x aawgd`
6. Open `/etc/init.d/S93aawgd` and<br> repalce `start-stop-daemon -S -b -q -m -p "$PIDFILE" -x "/usr/bin/$DAEMON"`<br> with `start-stop-daemon -S -b -q -m -p "$PIDFILE" -x "/usr/bin/$DAEMON" -- -d -s5 -c`
7. Restart RPi

## Troubleshooting
Sometimes deleting the system Bluetooth cache at /var/lib/bluetooth and restarting bluetoothd fixes persistent issues with device connectivity.
Consider also using "Forget" of bluetooth device in the Android phone.

Application by default is logging into _/var/log/aa-proxy-rs.log_ file. This log could be helpful when trying to solve issues.

## Hardening / making system read-only
Sometimes it is desirable (because of SD cards longevity) to make a whole system read-only. This would also help because we don't have any control when the car headunit is powering off the dongle (USB port).<br>
In some corner cases the filesystem could be damaged because the system is not properly shutdown and unmounted.

When you have the dongle set up properly and it is working as intended (you was connecting with your phone to the car, BT was paired, AA is working) you can make the following changes in the SD card:

_Partition #1 (boot):_<br>
edit the `cmdline.txt` file and add `ro` at the end of the line

_Partition #2 (main filesystem):_
```diff
--- old/etc/fstab	2024-03-30 17:44:15.000000000 +0100
+++ new/etc/fstab	2024-05-03 16:33:48.083059982 +0200
@@ -1,5 +1,5 @@
 # <file system>	<mount pt>	<type>	<options>	<dump>	<pass>
-/dev/root	/		ext2	rw,noauto	0	1
+/dev/root	/		ext2	ro,noauto	0	1
 proc		/proc		proc	defaults	0	0
 devpts		/dev/pts	devpts	defaults,gid=5,mode=620,ptmxmode=0666	0	0
 tmpfs		/dev/shm	tmpfs	mode=0777	0	0
diff -Nru 22/etc/inittab pizero-aa-backup/p2/etc/inittab
--- old/etc/inittab	2024-03-30 18:57:51.000000000 +0100
+++ new/etc/inittab	2024-05-03 16:45:24.184119996 +0200
@@ -15,7 +15,7 @@

 # Startup the system
 ::sysinit:/bin/mount -t proc proc /proc
-::sysinit:/bin/mount -o remount,rw /
+#::sysinit:/bin/mount -o remount,rw /
 ::sysinit:/bin/mkdir -p /dev/pts /dev/shm
 ::sysinit:/bin/mount -a
 ::sysinit:/bin/mkdir -p /run/lock/subsys
```

Again: before doing this, make sure that you've connect your phone at least once and all is working fine, specifically the `/var/lib/bluetooth/` directory is populated with your phone pairing information.<br>
This way after reboot all partitions will stay in read-only mode and should work longer and without possible problems.

If you want to make some changes to the filesystem or pair new phone you should revert those changes and it will be read-write again.<br>
It should be also possible to `ssh` and execute:<br>
`mount -o remount,rw /`<br>
to make root filesystem read-write again temporarily.

## Known problems
During my development work I encountered the stuck USB adapter once. What is more interesting, a reboots doesn't help, I had to re-power cycle the Pi.
In the `dmesg` I've got this:
```
Jan  1 00:00:02 buildroot kern.info kernel: [    1.775627] Bluetooth: hci0: BCM: chip id 94
Jan  1 00:00:02 buildroot kern.info kernel: [    1.779290] Bluetooth: hci0: BCM: features 0x2e
Jan  1 00:00:02 buildroot kern.info kernel: [    1.793222] Bluetooth: hci0: BCM43430A1
Jan  1 00:00:02 buildroot kern.info kernel: [    1.795614] Bluetooth: hci0: BCM43430A1 (001.002.009) build 0000
Jan  1 00:00:02 buildroot kern.info kernel: [    1.801062] Bluetooth: hci0: BCM43430A1 'brcm/BCM43430A1.raspberrypi,model-zero-2-w.hcd' Patch
Jan  1 00:00:04 buildroot kern.info kernel: [    4.436283] Bluetooth: hci0: BCM: features 0x2e
Jan  1 00:00:04 buildroot kern.err  kernel: [    4.438581] Bluetooth: hci0: Frame reassembly failed (-84)
Jan  1 00:00:04 buildroot kern.warn kernel: [    4.438627] Bluetooth: hci0: Received unexpected HCI Event 0x00
Jan  1 00:00:04 buildroot kern.err  kernel: [    4.440329] Bluetooth: hci0: Frame reassembly failed (-84)
Jan  1 00:00:06 buildroot kern.err  kernel: [    6.473578] Bluetooth: hci0: command 0x0c14 tx timeout
Jan  1 00:00:14 buildroot kern.err  kernel: [   14.553559] Bluetooth: hci0: BCM: Reading local name failed (-110)
```
And this was leading to problem with `aawgd`:
```
Jan  1 00:00:04 buildroot user.info aawgd[237]: Did not find any bluetooth adapters
```
As well as in aa-proxy-rs which cannot find bluetooth adapter.
I didn't go further investigating this problem, only noticing.

## Similar projects
- https://github.com/nisargjhaveri/WirelessAndroidAutoDongle
- https://github.com/nisargjhaveri/AAWirelessGateway
- https://github.com/openDsh/openauto
- https://github.com/qhuyduong/AAGateway
- https://github.com/Demon000/web-auto
- https://github.com/f1xpl/openauto
