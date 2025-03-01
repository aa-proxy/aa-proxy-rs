# 🛸 aa-proxy-rs

## About
This is a Rust-Written proxy tool to bridge between wireless Android phone and a USB-wired car head unit for using Google's Android Auto.
Currently it is intended to run as a more-or-less drop-in replacement of the `aawgd` from the [WirelessAndroidAutoDongle](https://github.com/nisargjhaveri/WirelessAndroidAutoDongle) project.

## Features
- written in [Rust](https://www.rust-lang.org/): reliable code and minimized all memory related issues and bugs
- fast: main IO loop is using modern [io_uring](https://kernel.dk/io_uring.pdf) kernel API
- reconnecting: trying to reconnect/recover AndroidAuto connection in any possible case
- bandwidth/transfer statistics
- stall transfer detection

## Current project status
Now after a lot of stress-testing and coding I think the project has matured enough, that I can say that the main stability goal was reached.
I am using this project almost daily in my car and trying to get rid of all issues I may encounter.

## SD card images
I am using Nisarg's RaspberryPi images from [WirelessAndroidAutoDongle](https://github.com/nisargjhaveri/WirelessAndroidAutoDongle) project and replacing `aawgd` with `aa-proxy-rs`.<br>
Those images are available on the [Release page](https://github.com/manio/aa-proxy-rs/releases).<br>
You can also find there a pure `aa-proxy-rs` binary which you can install manually on targets with similar libc versions, or build your own (read below: [Installing into target](#installing-into-target) and [Building](#building)).

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
- Currently only the default "connection strategy" is supported.
- Because the project main functionality (data transfer) is dependent on kernel [io_uring](https://kernel.dk/io_uring.pdf) API, the Linux kernel has to be in version 5.10 or later.
- My time resources are limited, so don't expect to prompt answers and ETAs on different requests. I am doing this as a hobby in my spare time.

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

## Building
`rpi02w` binaries build by [WirelessAndroidAutoDongle](https://github.com/nisargjhaveri/WirelessAndroidAutoDongle) are for `arm-unknown-linux-gnueabihf` 32-bit architecture, probably
because of usb-gadget module [incompatibility](https://github.com/nisargjhaveri/WirelessAndroidAutoDongle/pull/129).
To be able to properly crosscompile output binary I provided `.cargo/config.toml` with target set for this specific arch.

### Dependencies
1. [Installing Rust](https://www.rust-lang.org/tools/install)
2. `gcc-arm-linux-gnueabihf` package is needed on Debian. This is distro-depended so I recommend to RTFM.

To compile you need to add proper rustup target with:
```
rustup target add arm-unknown-linux-gnueabihf
```
and make sure that it is _installed_ on target list:
```
arm-unknown-linux-gnueabihf (installed)
```
and then use:
```
cargo build --release
```

To compile a STATIC `aa-proxy-rs` binary (to be able to use it on target with older OSes and different libc versions), you need to compile with:
```
RUSTFLAGS='-C target-feature=+crt-static' cargo build --release
```

## Building using Docker
To build with Docker you need to have a [buildx](https://github.com/docker/buildx) and [BuildKit](https://github.com/moby/buildkit).<br>
Docker container is also preparing an SD card images based on [@nisargjhaveri](https://github.com/nisargjhaveri)'s [latests assets](https://github.com/nisargjhaveri/WirelessAndroidAutoDongle/releases).
It has to loop-mount that images, thus an insecure builder is [needed](https://docs.docker.com/reference/cli/docker/buildx/build/#allow).
To sum it up - the following commands are needed when building for the first time:
```
mkdir out
docker buildx create --use --name insecure-builder --buildkitd-flags '--allow-insecure-entitlement security.insecure'
docker buildx build --builder insecure-builder --allow security.insecure --output out .
```
After successful execution the resulting `aa-proxy-rs` and SD card images will be in `out` directory.

## Installing into target
If you currently using a Raspberry Pi with working _WirelessAndroidAutoDongle_, then you can also manually install `aa-proxy-rs`:

You need to transfer the resulting output binary to the target filesystem and start it. I am using ssh/scp for this, but it should be also possible with `wget`.
You can also do it "offline" by making a changes directly on the SD card: mounting system partition and make necessary changes.
Sample [startup script](https://raw.githubusercontent.com/manio/aa-proxy-rs/refs/heads/main/contrib/S93aa-proxy-rs) is provided for convenience.

Example steps:
- put `aa-proxy-rs` into /usr/bin
- put `S93aa-proxy-rs` into /etc/init.d
- remove or disable /etc/init.d/S93aawgd

Startup parameters (see below) are defined [here](https://github.com/manio/aa-proxy-rs/blob/main/contrib/S93aa-proxy-rs#L10).

## Usage
```
aa-proxy-rs 0.2.0
AndroidAuto wired/wireless proxy

USAGE:
    aa-proxy-rs [OPTIONS]

OPTIONS:
    -a, --advertise
            BLE advertising

    -b, --btalias <BTALIAS>
            BLE device name

    -c, --connect <CONNECT>
            Auto-connect to saved phone or specified phone MAC address if provided

    -d, --debug
            Enable debug info

    -h, --help
            Print help information

        --hostapd-conf <HOSTAPD_CONF>
            hostapd.conf file location [default: /etc/hostapd.conf]

    -i, --iface <IFACE>
            WLAN / Wi-Fi Hotspot interface [default: wlan0]

    -k, --keepalive
            Keep alive mode: BLE adapter doesn't turn off after successful connection, so that the
            phone can remain connected (used in special configurations)

    -l, --legacy
            Enable legacy mode

    -l, --logfile <LOGFILE>
            Log file path [default: /var/log/aa-proxy-rs.log]

    -s, --stats-interval <SECONDS>
            Interval of showing data transfer statistics (0 = disabled) [default: 0]

    -t, --timeout-secs <SECONDS>
            Data transfer timeout [default: 5]

    -u, --udc <UDC>
            UDC Controller name

    -V, --version
            Print version information
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

## Troubleshooting
Sometimes deleting the system Bluetooth cache at /var/lib/bluetooth and restarting bluetoothd fixes persistent issues with device connectivity.
Consider also using "Forget" of bluetooth device in the Android phone.

Application by default is logging into _/var/log/aa-proxy-rs.log_ file. This log could be helpful when trying to solve issues.
If you want to get logs out of device, read [here](https://github.com/nisargjhaveri/WirelessAndroidAutoDongle?tab=readme-ov-file#getting-logs) how to obtain it.

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

## Similar/other open source AndroidAuto-related projects
- https://github.com/nisargjhaveri/WirelessAndroidAutoDongle
- https://github.com/nisargjhaveri/AAWirelessGateway
- https://github.com/openDsh/openauto
- https://github.com/qhuyduong/AAGateway
- https://github.com/Demon000/web-auto
- https://github.com/f1xpl/openauto
- https://github.com/gamelaster/opengal_proxy
- https://github.com/tomasz-grobelny/AACS
