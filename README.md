# :joystick: apk.py
apk.py is a Python script that makes reverse engineering Android apps easier, automating some repetitive tasks like pulling, decoding, rebuilding and patching an APK.


## Features
apk.py basically uses [apktool](https://ibotpeaches.github.io/Apktool/) to disassemble, decode and rebuild resources and some python to automate the [frida](https://https://frida.re/) gadget injection process.
It also supports app bundles/split APKs. 

 -  :mushroom: Patching APKs to load frida-gadget.so on start.
 -  :new: Support for app bundles/split APKs.
 -  :wrench: Disassembling resources to nearly original form with apktool.
 -  :nut_and_bolt: Rebuilding decoded resources back to binary APK/JAR with apktool.
 -  :old_key: Code signing the apk with apksigner.
 -  :desktop_computer: Multiple arch support (arm, arm64, x86, x86_64). 
 -  :no_mobile_phones: No rooted Android device needed.


## Getting started
:arrow_left: Pulling an APK from a device is simple as running `./apk.py --pull <package_name>`

:wrench: Decoding an APK is simple as running `./apk.py --decode <apk_name>`

:nut_and_bolt: Rebuilding an APK is simple as running  `./apk.py --build <apk_dir>`


## apk.py pull
`apk.py --pull` pull an APK from a device.
It supports app bundles/split APKs, which means that split APKs will be joined in a single APK (this is useful for patching). 
If the package is an app bundle/split APK, apk.py will combine the APKs into a single APK, fixing all public resource identifiers.


## apk.py patch
`apk.py --patch` patch an APK to load [frida-gadget.so](https://frida.re/docs/gadget/) on start.

frida-gadget.so is a Frida's shared library meant to be loaded by programs to be instrumented (when the Injected mode of operation isn’t suitable). By simply loading the library it will allow you to interact with it using existing Frida-based tools like frida-trace. It also supports a fully autonomous approach where it can run scripts off the filesystem without any outside communication.

Patching an APK is simple as running  `./apk.py --patch <apk_name> --arch arm`.

You can calso specify a Frida gadget configuration in a json `./apk.py --patch <apk_name> --arch arm --gadget-conf <config.json>`

## :mushroom: Frida's Gadget configurations
In the default interaction, Frida Gadget exposes a frida-server compatible interface, listening on localhost:27042 by default. In order to achieve early instrumentation Frida let Gadget’s constructor function block until you either `attach()` to the process, or call `resume()` after going through the usual `spawn()` -> `attach()` -> `...apply instrumentation...` steps.

If you don’t want this blocking behavior and want to let the program boot right up, or you’d prefer it listening on a different interface or port, you can customize this through a json configuration file.

The default configuration is:
```json
{
  "interaction": {
    "type": "listen",
    "address": "127.0.0.1",
    "port": 27042,
    "on_port_conflict": "fail",
    "on_load": "wait"
  }
}
```

You can pass the gadget configuration file to `apk.py` with the `--gadget-conf` option.

### Script interaction

A typically suggested configuration might be:
```json
{
  "interaction": {
    "type": "script",
    "path": "/data/local/tmp/script.js",
    "on_change":"reload"
  }
}
```

script.js could be something like:

```javascript
var android_log_write = new NativeFunction(
    Module.getExportByName(null, '__android_log_write'),
    'int',
    ['int', 'pointer', 'pointer']
);

var tag = Memory.allocUtf8String("[frida-script][81U380X]");

var work = function() {
    setTimeout(function() {
        android_log_write(3, tag, Memory.allocUtf8String("ping @ " + Date.now()));
        work();
    }, 1000);
}

work();

android_log_write(3, tag, Memory.allocUtf8String(">--(O.o)-<"));
```
`adb push script.js /data/local/tmp`

`./apk.py patch <apk_name> --arch arm --gadget-conf <config.json>`

`adb install file.gadget.apk`

### Note
Add the following code to print to logcat the `console.log` output of any script from the [frida codeshare](https://codeshare.frida.re/) when using the Script interaction type.
```js
// print to logcat the console.log output
// see: https://github.com/frida/frida/issues/382
var android_log_write = new NativeFunction(
    Module.getExportByName(null, '__android_log_write'),
    'int',
    ['int', 'pointer', 'pointer']
);
var tag = Memory.allocUtf8String("[frida-script][81U380X]");
console.log = function(str) {
    android_log_write(3, tag, Memory.allocUtf8String(str));
}
```

## Requirements

- apktool
- apksigner
- unxz
- zipalign
- aapt
- adb

## Usage 
### SYNOPSIS
	apk.py [SUBCOMMAND] [APK FILE|APK DIR|PKG NAME] [FLAGS]
	apk.py --pull [PKG NAME] [FLAGS]
	apk.py --decode [APK FILE] [FLAGS]
	apk.py --build [APK DIR] [FLAGS]
	apk.py --patch [APK FILE] [FLAGS]
	apk.py --rename [APK FILE] [PKG NAME] [FLAGS]

 ### SUBCOMMANDS
	pull	Pull an apk from device/emulator.
	decode	Decode an apk.
	build	Re-build an apk.
	patch	Patch an apk.
	rename	Rename the apk package.

 ### FLAGS
`-a, --arch <arch>` Specify the target architecture, mandatory when patching.

`-g, --gadget-conf <json_file>` Specify a frida-gadget configuration file, optional when patching.

`-n, --net` Add a permissive network security config when building, optional. It can be used with patch, pull and rename also.

`-s, --safe` Do not decode resources when decoding (i.e. apktool -r). Cannot be used when patching.

`-d, --no-dis` Do not disassemble dex, optional when decoding (i.e. apktool -s). Cannot be used when patching.


## :page_with_curl: Links of Interest
https://frida.re/docs/gadget/

https://lief-project.github.io/doc/latest/tutorials/09_frida_lief.html

https://koz.io/using-frida-on-android-without-root/

https://github.com/sensepost/objection/

https://github.com/NickstaDB/patch-apk/

https://neo-geo2.gitbook.io/adventures-on-security/frida-scripting-guide/frida-scripting-guide
