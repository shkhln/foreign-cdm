# foreign-cdm

A native FreeBSD CDM implementation that is actually a wrapper
for the real thing running under the Linux emulation layer.

Works with Chromium, doesn't work with Firefox (at the moment).

## Usage

Normally you want to install this from packages:

```
% sudo sysrc linux_enable="YES"
% sudo service linux start
% sudo pkg install foreign-cdm
```

Obtain Widevine or whatever, launch Chromium and try to play protected content.
Terminate the browser and launch it again. (For unclear reasons
the playback _must_ fail once for Chromium to register the CDM.)

Alternatively, to test this do:

```
% sudo pkg install linux-rl9-devtools
% git clone --recurse-submodules <this repo>
% cd foreign-cdm
% make all DEBUG=y
% sudo chown root build/fcdm-jail
% ./chrome.sh
```
