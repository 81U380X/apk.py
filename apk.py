"""
apk.py v1.0.4
author: 81U380X - github.com/81U380X

-----------------------------------------------------------------------------

SYNOPSIS
    apk.py [SUBCOMMAND] [APK FILE|APK DIR|PKG NAME] [FLAGS]
    apk.py pull [PKG NAME] [FLAGS]
    apk.py decode [APK FILE] [FLAGS]
    apk.py build [APK DIR] [FLAGS]
    apk.py patch [APK FILE] [FLAGS]
    apk.py rename [APK FILE] [PKG NAME] [FLAGS]

SUBCOMMANDS
    pull	Pull an apk from device/emulator.
    decode	Decode an apk.
    build	Re-build an apk.
    patch	Patch an apk.
    rename	Rename the apk package.

FLAGS
    -a, --arch <arch>	Specify the target architecture, mandatory when patching.

    -g, --gadget-conf <json_file>
                Specify a frida-gadget configuration file, optional when patching.

    -n, --net		Add a permissing network security config when building, optional.
                It can be used with patch, pull and rename also.

    -s, --safe		Do not decode resources when decoding (i.e. apktool -r).
                Cannot be used when patching.

    -d, --no-dis		Do not disassemble dex, optional when decoding (i.e. apktool -s).
                Cannot be used when patching.

-----------------------------------------------------------------------------
"""
import argparse
import lzma
import os
import platform
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import requests
from pick import pick
from rich.progress import Progress

DEBUG = False
VERSION = "1.0.4"
print(f"[*] \033[1mapk.py v{VERSION} \033[0m")
APK_SH_HOME = Path.home() / ".apk.py"
APK_SH_HOME.mkdir(parents=True, exist_ok=True)
print(f"[*] home dir is {APK_SH_HOME}")

SUPPORTED_ARCH = ("arm", "x86_64", "x86", "arm64")


def print_(value: any) -> None:
    if DEBUG:
        print(value)


print_("[*] DEBUG is TRUE")

APKTOOL_VER = "2.7.0"
APKTOOL_PATH = APK_SH_HOME / f"apktool_{APKTOOL_VER}.jar"

BUILDTOOLS_VER = "33.0.1"
SDK_ROOT = APK_SH_HOME / "sdk_root"
BUILD_TOOLS = SDK_ROOT / "build-tools" / BUILDTOOLS_VER

if not BUILD_TOOLS.is_dir():
    APKSIGNER = "apksigner"
    ZIPALIGN = "zipalign"
    AAPT = "aapt"
else:
    APKSIGNER = BUILD_TOOLS / "apksigner"
    ZIPALIGN = BUILD_TOOLS / "zipalign"
    AAPT = BUILD_TOOLS / "aapt"


def wget(path: Path, url: str) -> None:
    with Progress() as progress:
        response = requests.request(method="GET", url=url, stream=True)
        task = progress.add_task(path.name, total=int(response.headers.get("Content-Length", 0)))

        with open(path, mode="wb") as file:
            for data in response.iter_content(chunk_size=1024):
                file.write(data)
                progress.update(task, advance=len(data))
        progress.stop()


def install_buildtools() -> None:
    system = {"Windows": "win", "Linux": "linux"}.get(platform.system(), None)
    if not system:
        raise NotImplemented(f"Unsupported operating system: {platform.system()}")
    CMDLINE_TOOLS_DOWNLOAD_URL = f"https://dl.google.com/android/repository/commandlinetools-{system}-9123335_latest.zip"
    CMDLINE_TOOLS_ZIP = APK_SH_HOME / Path(CMDLINE_TOOLS_DOWNLOAD_URL).name
    CMDLINE_TOOLS_DIR = APK_SH_HOME / "cmdline-tools"

    if not CMDLINE_TOOLS_DIR.is_dir():
        print(f"[>] Downloading Android commandline tools from {CMDLINE_TOOLS_DOWNLOAD_URL}")
        wget(path=CMDLINE_TOOLS_ZIP, url=CMDLINE_TOOLS_DOWNLOAD_URL)
        with zipfile.ZipFile(CMDLINE_TOOLS_ZIP, mode="r") as zip_ref:
            zip_ref.extractall(APK_SH_HOME)
        CMDLINE_TOOLS_ZIP.unlink()

    SDK_MANAGER_BIN = CMDLINE_TOOLS_DIR / "bin" / "sdkmanager"
    SDK_ROOT.mkdir(parents=True, exist_ok=True)
    INSTALL_BUILDTOOLS_CMD = f"{SDK_MANAGER_BIN} build-tools;{BUILDTOOLS_VER} --sdk_root={SDK_ROOT}"
    option, index = pick(["No", "Yes"], f"Install build-tools {BUILDTOOLS_VER}?")
    if index == 0:
        sys.exit(0)
    print(f"[>] Installing build-tools {BUILDTOOLS_VER}...")
    run(INSTALL_BUILDTOOLS_CMD)
    APKSIGNER = BUILD_TOOLS / "apksigner"
    ZIPALIGN = BUILD_TOOLS / "zipalign"
    AAPT = BUILD_TOOLS / "aapt"
    print("[>] Done!")


def check_apk_tools() -> None:
    if APKTOOL_PATH.is_file():
        print(f"[*] apktool v{APKTOOL_VER} exist in {APK_SH_HOME}")
    else:
        APKTOOL_DOWNLOAD_URL_BB = f"https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_{APKTOOL_VER}.jar"
        APKTOOL_DOWNLOAD_URL_GH = f"https://github.com/iBotPeaches/Apktool/releases/download/v{APKTOOL_VER}/apktool_{APKTOOL_VER}.jar"
        APKTOOL_DOWNLOAD_URL = APKTOOL_DOWNLOAD_URL_GH
        print(f"[!] No apktool v{APKTOOL_VER} found!")
        print(f"[>] Downloading apktool from {APKTOOL_DOWNLOAD_URL}")
        wget(path=APK_SH_HOME / Path(APKTOOL_DOWNLOAD_URL).name, url=APKTOOL_DOWNLOAD_URL)

    if is_not_installed("apksigner"):
        if not APKSIGNER.is_file():
            print("[!] No apksigner found in path!")
            print(f"[!] No apksigner found in {APK_SH_HOME}")
            install_buildtools()
            print("[>] apksigner installed!")
        else:
            version = subprocess.check_output([APKSIGNER, "--version"], text=True).strip()
            print(f"[*] apksigner v{version} exist in {BUILD_TOOLS}")

    if is_not_installed("zipalign"):
        if not ZIPALIGN.is_file():
            install_buildtools()
            print("[>] zipalign installed!")
        else:
            print(f"[*] zipalign exist in {BUILD_TOOLS}")
    if is_not_installed("aapt"):
        if not AAPT.is_file():
            install_buildtools()
            print("[>] aapt installed!")
        else:
            print(f"[*] aapt exist in {BUILD_TOOLS}")


def is_not_installed(command: str) -> bool:
    return shutil.which(command) is None


def exit_if_not_exist(path: Path) -> None:
    if not path.exists():
        print(f"[!] File {path} not found!")
        print("[>] Bye!")
        sys.exit(1)


def run(cmd: str) -> None:
    try:
        subprocess.run(cmd, shell=True, check=True)
    except subprocess.CalledProcessError:
        print("[>] Sorry!")
        print(f"[!] Command failed: {cmd}")
        print("[>] Bye!")
        sys.exit(1)


def apk_build(path: Path, options: str) -> None:
    APK_DIR = path
    BUILD_CMD_OPTS = options.strip()
    BUILD_CMD_START = f"java -jar {APKTOOL_PATH} b -d"
    BUILD_CMD = f"{BUILD_CMD_START} {APK_DIR} {BUILD_CMD_OPTS}"
    match = re.search(r"-o\s(\S+)", BUILD_CMD_OPTS)
    APK_NAME = match.group(1) if match else f"{APK_DIR.name}.apk"
    if " -n" in BUILD_CMD_OPTS:
        (APK_DIR / "res" / "xml").mkdir(parents=True, exist_ok=True)
    print(f"[>] \033[1mBuilding\033[0m with {BUILD_CMD}")
    run(BUILD_CMD)
    print("[>] Built!")
    print("[>] Aligning with zipalign -p 4 ....")
    run(f"{ZIPALIGN} -p 4 {APK_NAME} {APK_NAME}-aligned.apk")
    print("[>] Done!")

    KS = APK_SH_HOME / "my-new.keystore"
    if not KS.is_file():
        print("[!] Keystore does not exist!")
        print("[>] Generating keystore...")
        run(f'keytool -genkey -v -keystore {KS} -alias alias_name -keyalg RSA -keysize 2048 -validity 10000 -storepass password -keypass password -noprompt -dname "CN=noway, OU=ID, O=Org, L=Blabla, S=Blabla, C=US"')
    else:
        print("[>] A Keystore exist!")
    print(f"[>] Signing {APK_NAME} with apksigner...")
    run(f'{APKSIGNER} sign --ks {KS} --ks-pass pass:password "{APK_NAME}-aligned.apk"')
    os.remove(APK_NAME)
    os.rename(f"{APK_NAME}-aligned.apk", APK_NAME)
    print("[>] Done!")
    print(f"[>] {APK_NAME} ready!")


def apk_decode(path: Path, options: str) -> None:
    APK_NAME = path
    DECODE_CMD_OPTS = options
    DECODE_CMD_START = f"java -jar {APKTOOL_PATH} d"
    DECODE_CMD = f"{DECODE_CMD_START} {APK_NAME} {DECODE_CMD_OPTS}"
    print(f"[>] \033[1mDecoding {APK_NAME}\033[0m with {DECODE_CMD}")
    run(DECODE_CMD)
    print("[>] Done!")


def apk_patch(path: Path, arch: str, config: Path, options: str) -> None:
    # Frida gadget exposes a frida-server compatible interface, listening on localhost:27042 by default.
    # run as soon as possible: frida -D emulator-5554 -n Gadget

    APK_NAME = path
    ARCH = arch
    GADGET_CONF_PATH = config
    BUILD_OPTS = options
    GADGET_VER = "15.1.28"

    print(f"[>] \033[1mPatching {APK_NAME} injecting gadget for {ARCH}...\033[0m")
    ARCH_DIR = ("armeabi-v7a", "x86_64", "x86", "arm64-v8a")[SUPPORTED_ARCH.index(ARCH)]
    GADGET = f"frida-gadget-{GADGET_VER}-android-{ARCH}.so.xz"

    FRIDA_SO_XZ = APK_SH_HOME / GADGET
    FRIDA_SO = FRIDA_SO_XZ.parent / FRIDA_SO_XZ.stem

    if not FRIDA_SO.is_file():
        if not FRIDA_SO_XZ.is_file():
            print(f"[!] Frida gadget not present in {APK_SH_HOME}")
            print(f"[>] Downloading latest frida gadget for {ARCH} from github.com...")
            wget(path=FRIDA_SO_XZ, url=f"https://github.com/frida/frida/releases/download/{GADGET_VER}/{GADGET}")
        with lzma.open(FRIDA_SO_XZ, mode="rb") as xz_file:
            with open(FRIDA_SO, mode="wb") as output:
                shutil.copyfileobj(xz_file, output)
    else:
        print(f"[>] Frida gadget already present in {APK_SH_HOME}")
    print(f"[>] Using {FRIDA_SO}")

    APKTOOL_DECODE_OPTS = ""
    apk_decode(path=APK_NAME, options=APKTOOL_DECODE_OPTS)

    print("[>] \033[1mInjecting Frida gadget...\033[0m")
    print(f"[>] Placing the Frida shared object for {ARCH}....")
    APK_DIR = APK_NAME.parent / APK_NAME.stem

    (APK_DIR / "lib" / ARCH_DIR).mkdir(parents=True, exist_ok=True)
    shutil.copyfile(FRIDA_SO, (APK_DIR / "lib" / ARCH_DIR / "libfrida-gadget.so"))
    if GADGET_CONF_PATH:
        print("[>] Placing the specified gadget configuration json file....")
        shutil.copyfile(GADGET_CONF_PATH, (APK_DIR / "lib" / ARCH_DIR / "libfrida-gadget.config.so"))

    # Inject a System.loadLibrary("frida-gadget") call into the smali,
    # before any other bytecode executes or any native code is loaded.
    # A suitable place is typically the static initializer of the entry point class of the app (e.g. the main application Activity).
    # We have to determine the class name for the activity that is launched on application startup.
    # In Objection this is done by first trying to parse the output of aapt dump badging, then falling back to manually parsing the AndroidManifest for activity-alias tags.
    print("[>] Searching for a launchable-activity...")
    output = subprocess.check_output(f"aapt dump badging {APK_NAME}", shell=True, text=True)
    MAIN_ACTIVITY = re.search(r"launchable-activity: name='([^']+)'", output).group(1)
    print(f"[>] launchable-activity found --> {MAIN_ACTIVITY}")
    # TODO: If we dont get the activity, we gonna check out activity aliases trying to manually parse the AndroidManifest.
    # Try to determine the local path for a target class' smali converting the main activity to a path
    MAIN_ACTIVITY_2PATH = MAIN_ACTIVITY.replace(".", "/")
    CLASS_PATH = Path(APK_DIR) / "smali" / f"{MAIN_ACTIVITY_2PATH}.smali"
    print(f"[>] Local path should be {CLASS_PATH}")
    # NOTE: if the class does not exist it might be a multidex setup.
    # Search the class in smali_classesN directories.
    CLASS_PATH_IND = 1  # starts from 2
    # get max number of smali_classes
    CLASS_PATH_IND_MAX = len(list(APK_DIR.glob("*_classes[0-9]*")))
    while not CLASS_PATH.is_file():
        print(f"[!] {CLASS_PATH} does not exist! Probably a multidex APK...")
        if CLASS_PATH_IND > CLASS_PATH_IND_MAX:
            # keep searching until smali_classesN then exit
            print(f"[>] {CLASS_PATH} NOT FOUND!")
            print("[!] Can't find the launchable-activity! Sorry.")
            print("[>] Bye!")
            sys.exit(1)
        CLASS_PATH_IND += 1
        # ./base/smali/
        # ./base/smali_classes2/
        CLASS_PATH = APK_DIR / f"smali_classes{CLASS_PATH_IND}" / f"{MAIN_ACTIVITY_2PATH}.smali"
        print(f"[?] Looking in {CLASS_PATH}...")

    """
    Now, patch the smali, look for the line with the apktool's comment "# direct methods" 
    Patch the smali with the appropriate loadLibrary call based on wether a constructor already exists or not.
    If an existing constructor is present, the partial_load_library will be used.
    If no constructor is present, the full_load_library will be used.
    
    Objection checks if there is an existing <clinit> to determine which is the constructor,
    then they inject a loadLibrary just before the method end.
    
    We search for *init> and inject a loadLibrary just after the .locals declaration.
    
    <init> is the (or one of the) constructor(s) for the instance, and non-static field initialization.
    <clinit> are the static initialization blocks for the class, and static field initialization.
    """

    print(f"[>] {CLASS_PATH} found!")
    print("[>] Patching smali...")
    lines = CLASS_PATH.read_text().splitlines()
    index = 0
    skip = 1
    for i in range(len(lines)):
        # partial_load_library
        if lines[i] == "# direct methods":
            if "init>" in lines[i + 1]:
                print(f"[>>] A constructor is already present --> {lines[index + 1]}")
                print("[>>] Injecting partial load library!")
                # Skip  any .locals and write after
                # Do we have to skip .annotaions? is ok to write before them?
                if ".locals" in lines[i + 2]:
                    print("[>>] .locals declaration found!")
                    print("[>>] Skipping .locals line...")
                    skip = 2
                    print("[>>] Update locals count...")
                    locals_count = int(lines[i + 2].split()[1]) + 1
                    lines[i + 2] = f".locals {locals_count}"
                else:
                    print("[!!!!!!] No .locals found! :(")
                    print("[!!!!!!] TODO add .locals line")

                # We inject a loadLibrary just after the locals delcaration.
                # Objection add the loadLibrary call just before the method end.
                arr = lines[: i + 1 + skip]  # start of the list
                arr.append('const-string v0, "frida-gadget"')
                arr.append('invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V')
                arr.extend(lines[i + 1 + skip:])  # tail of the list
                lines = arr  # assign back to the original list
            else:
                print("[!!!!!!] No constructor found!")
                print("[!!!!!!] TODO: gonna use the full load library")
                # arr.append('.method static constructor <clinit>()V')
                # arr.append('   .locals 1')
                # arr.append('')
                # arr.append('   .prologue')
                # arr.append('   const-string v0, "frida-gadget"')
                # arr.append('')
                # arr.append('   invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V')
                # arr.append('')
                # arr.append('   return-void')
                # arr.append('.end method')
        index += 1
    print("[>] Writing the pathced smali back...")
    CLASS_PATH.write_text("\n".join(lines))

    # Add the Internet permission to the manifest if it’s not there already, to permit Frida gadget to open a socket.
    print("[?] Checking if Internet permission is present in the manifest...")
    INTERNET_PERMISSION = False
    MANIFEST_PATH = APK_DIR / "AndroidManifest.xml"
    manifest = MANIFEST_PATH.read_text().splitlines()
    for i in manifest:
        if '<uses-permission android:name="android.permission.INTERNET"/>' in i:
            INTERNET_PERMISSION = True
            print("[>] Internet permission is there!")
            break
    if not INTERNET_PERMISSION:
        print("[!] Internet permission not present in the Manifest!")
        print(f"[>] Patching {MANIFEST_PATH}")
        arr = [manifest[0]]  # start of the list
        arr.append('<uses-permission android:name="android.permission.INTERNET"/>')
        arr.extend(manifest[1:])  # tail of the list
        MANIFEST_PATH.write_text("\n".join(arr))

    APKTOOL_BUILD_OPTS = f"-o {APK_DIR}.gadget.apk --use-aapt2"
    APKTOOL_BUILD_OPTS = f"{APKTOOL_BUILD_OPTS} {BUILD_OPTS}"
    apk_build(path=APK_DIR, options=APKTOOL_BUILD_OPTS)
    print("[>] Bye!")


def apk_pull(package: str, options: str) -> None:
    if is_not_installed("adb"):
        print("[>] No adb found!")
        print("[>] Pls install adb!")
        print("[>] Bye!")
        sys.exit(1)

    PACKAGE = package
    BUILD_OPTS = options
    output = subprocess.check_output(["adb", "shell", "pm", "path", PACKAGE], text=True).strip()
    PACKAGE_PATH = output.split(':')[1].strip() if output else None
    if not PACKAGE_PATH:
        print(f"[>] Sorry, cant find package {PACKAGE}")
        print("[>] Bye!")
        sys.exit(1)
    NUM_APK = len(PACKAGE_PATH.splitlines())
    if NUM_APK > 1:
        SPLIT_DIR = Path(PACKAGE + "_split_apks")
        SPLIT_DIR.mkdir(parents=True, exist_ok=True)
        print(f"[>] Pulling {PACKAGE}: Split apks detected!")
        print(f"[>] Pulling {NUM_APK} apks in {SPLIT_DIR}")
        print_(f"[>] Pulling {PACKAGE} from {PACKAGE_PATH}<<<")

        for package in PACKAGE_PATH.splitlines():
            PULL_CMD = f"adb pull {package} {SPLIT_DIR}"
            run(PULL_CMD)
        # We have to combine split APKs into a single APK, for patching.
        # Decode all the APKs.
        print("[>] Combining split APKs into a single APK...")
        SPLIT_APKS = list(SPLIT_DIR.glob("*.apk"))
        for i in SPLIT_APKS:
            APK_NAME = i
            print_(APK_NAME)
            APK_DIR = APK_NAME.parent / APK_NAME.stem
            APKTOOL_DECODE_OPTS = f"-o {APK_DIR}"
            apk_decode(path=APK_DIR, options=APKTOOL_DECODE_OPTS)

        # Walk the extracted APKs dirs and copy files and dirs to the base APK dir.
        print("[>] Walking extracted APKs dirs and copying files to the base APK...")
        for i in SPLIT_APKS:
            APK_NAME = i
            APK_DIR = APK_NAME.parent / APK_NAME.stem

            # Skip base.apk.
            if APK_DIR == (SPLIT_DIR / "base"):
                continue
            # Walk each apk dir.
            FILES_IN_SPLIT_APK = list(APK_DIR.glob("*"))
            for j in FILES_IN_SPLIT_APK:
                print_(f"[>>>>] Parsing split apks file: {j}")
                # Skip Manifest, apktool.yml, and the original files dir.
                if j.name in ["AndroidManifest.xml", "apktool.yml"] or "original" in j:
                    print_("[-] Skip!")
                    continue
                # Copy files into the base APK, except for XML files in the res directory
                if j.name == "res":
                    print_("[.] /res directory found!")
                    shutil.copytree(j, (SPLIT_DIR / "base" / "res"), ignore=shutil.ignore_patterns("*.xml"))
                print_(f"[>] Copying directory cp -R {j} in {SPLIT_DIR / 'base'} ....")
                shutil.copytree(j, (SPLIT_DIR / "base" / j.name))

        print("[>] Fixing APKTOOL_DUMMY public resource identifiers...")
        # Fix public resource identifiers.
        # Find all resource IDs with name APKTOOOL_DUMMY_xxx in the base dir
        DUMMY_IDS = re.findall(r'id="([^"]*?)"', (SPLIT_DIR / "base").read_text())
        for j in DUMMY_IDS:
            print_("[~] DUMMY_ID_TO_FIX:", j)
            # Get the dummy name grepping for the resource ID
            DUMMY_NAME = re.search(r'name="([^"]*?)"', Path(SPLIT_DIR, "base").read_text()).group(1)
            print_(f"[~] DUMMY_NAME: {DUMMY_NAME}")
            # Get the real resource name grepping for the resource ID in each spit APK
            REAL_NAME = re.search(r'name="([^"]*?)"', Path(SPLIT_DIR).read_text()).group(1)
            print_(f"[~] REAL_NAME: {REAL_NAME}")
            # Grep DUMMY_NAME and substitute the real resource name in the base dir
            file_list = [file for file in Path(SPLIT_DIR, "base").glob("*.xml") if DUMMY_NAME in file.read_text()]
            for file_path in file_list:
                print_(f"[~] File of base.apk with the DUMMY_NAME to update: {file_path}")
                file_content = file_path.read_text()
                updated_content = re.sub(r'\b' + DUMMY_NAME + r'\b', REAL_NAME, file_content)
                file_path.write_text(updated_content)
                print_("---")

        print("[>] Done!")
        # Disable APK splitting in the base manifest file, if it’s not there already done.
        MANIFEST_PATH = SPLIT_DIR / "base" / "AndroidManifest.xml"
        print("[>] Disabling APK splitting (isSplitRequired=false) if it was set to true...")
        manifest_content = MANIFEST_PATH.read_text()
        updated_manifest_content = manifest_content.replace('android:isSplitRequired="true"', 'android:isSplitRequired="false"')
        MANIFEST_PATH.write_text(updated_manifest_content)
        # Set android:extractNativeLibs="true" in the Manifest if you experience any adb: failed to install file.gadget.apk:
        # Failure [INSTALL_FAILED_INVALID_APK: Failed to extract native libraries, res=-2]
        print("[>] Enabling native libraries extraction if it was set to false...")
        # If the tag exist and is set to false, set it to true, otherwise do nothing
        updated_manifest_content = manifest_content.replace('android:extractNativeLibs="false"', 'android:extractNativeLibs="true"')
        MANIFEST_PATH.write_text(updated_manifest_content)
        print("[>] Done!")
        # Rebuild the base APK
        APKTOOL_BUILD_OPTS = "-o file.single.apk --use-aapt2"
        APKTOOL_BUILD_OPTS = f"{APKTOOL_BUILD_OPTS} {BUILD_OPTS}"
        apk_build(path=(SPLIT_DIR / "base"), options=APKTOOL_BUILD_OPTS)
        print("[>] Bye!")
    else:
        print(f"[>] Pulling {PACKAGE} from {PACKAGE_PATH}")
        PULL_CMD = f"adb pull {PACKAGE_PATH} ."
        run(PULL_CMD)
        print("[>] Done!")
        print("[>] Bye!")


def apk_rename(path: Path, package: str, options: str) -> None:
    APK_NAME = path
    PACKAGE = package
    BUILD_OPTS = options
    print(f"[>] \033[1mRenaming {APK_NAME}\033[0m to {PACKAGE}")
    apk_decode(path=APK_NAME, options="")
    APK_DIR = APK_NAME.parent / APK_NAME.stem
    APKTOOL_YML_PATH = APK_DIR / "apktool.yml"
    print(f"[>] Updating renameManifestPackage in apktool.yml with {PACKAGE}")
    # Note: https://github.com/iBotPeaches/Apktool/issues/1753
    # renameManifestPackage is not designed for manual package name changes, but can be useful in some situations.
    file_content = APKTOOL_YML_PATH.read_text()
    updated_content = re.sub(r'renameManifestPackage:.+', f'renameManifestPackage: {PACKAGE}', file_content)
    APKTOOL_YML_PATH.write_text(updated_content)
    APKTOOL_BUILD_OPTS = f"-o file.renamed.apk --use-aapt2 {BUILD_OPTS}"
    # Silently build
    apk_build(path=APK_DIR, options=APKTOOL_BUILD_OPTS)


if __name__ == "__main__":
    check_apk_tools()
    parser = argparse.ArgumentParser(
        description=
        """
        Apk.py is a command-line utility for working with Android application packages (APKs). It provides decoding, patching, pulling, renaming, and other functionalities for APK files. It is a valuable tool for Android developers and researchers.
        """,
        epilog=
        """
        Thank you for using APK Tool! We hope it has been helpful for your Android development and research tasks. If you have any feedback or suggestions, feel free to reach out. Happy APK manipulation!
        """)
    parser.add_argument("--build", type=str, metavar="DIR", help="apk dir")
    parser.add_argument("--decode", type=str, metavar="FILE", help="apk dir")
    parser.add_argument("--patch", type=str, metavar="FILE", help="apk dir")
    parser.add_argument("--pull", action="store_true", help="package name")
    parser.add_argument("--rename", type=str, metavar="FILE", help="rename apk")
    parser.add_argument("--package", "-p", type=str, help="package apk")
    parser.add_argument("--net", "-n", action="store_true")
    parser.add_argument("--safe", "-s", action="store_true", help="no decode res")
    parser.add_argument("--disass", "-d", action="store_true", help="no disass dex")
    parser.add_argument("--gadget-conf", "-g", type=str, metavar="FILE", help="Gadget configuration")
    parser.add_argument("--arch", choices=SUPPORTED_ARCH)
    parser.add_argument("--positional", type=str, nargs='*', help="positional args")
    parser.required_args = ["build", "decode", "patch", "pull", "rename"]
    args = parser.parse_args()

    if args.build:
        """
        It seems there is a problem with apktool build and manifest attribute android:dataExtractionRules 
            : /home/81U380X/AndroidManifest.xml:30: error: attribute android:dataExtractionRules not found.
            W: error: failed processing manifest.
        Temporary workaround: remove the attribute from the Manifest and use Android 9 
        
        Set android:extractNativeLibs="true" in the Manifest if you experience any adb:
        failed to install file.gadget.apk: Failure [INSTALL_FAILED_INVALID_APK: Failed to extract native libraries, res=-2]
        https://github.com/iBotPeaches/Apktool/issues/1626 - zipalign -p 4 seems to not resolve the issue.
        """
        APK_DIR = Path(args.build)
        exit_if_not_exist(APK_DIR)
        APKTOOL_BUILD_OPTS = "-o file.apk --use-aapt2"
        # APKTOOL_BUILD_OPTS = "--use-aapt2"
        if args.net:
            APKTOOL_BUILD_OPTS += " -n"
        if args.positional:
            APKTOOL_BUILD_OPTS += f" {args.positional}"

        apk_build(path=APK_DIR, options=APKTOOL_BUILD_OPTS)
        sys.exit(0)
    elif args.decode:
        APK_NAME = Path(args.decode)
        exit_if_not_exist(APK_NAME)
        APKTOOL_DECODE_OPTS = ""
        if args.safe:
            APKTOOL_DECODE_OPTS += " -r"
        if args.disass:
            APKTOOL_DECODE_OPTS += " -s"
        if args.positional:
            APKTOOL_DECODE_OPTS += f" {args.positional}"

        apk_decode(path=APK_NAME, options=APKTOOL_DECODE_OPTS)
        sys.exit(0)
    elif args.patch:
        APK_NAME = Path(args.patch)
        exit_if_not_exist(APK_NAME)

        GADGET_CONF_PATH = None
        APKTOOL_BUILD_OPTS = ""

        if not args.arch:
            print("Pass the apk name and the arch param!")
            print("./apk --patch <apkname.apk> --arch <arch>")
            print("[>] Bye!")
            sys.exit(1)

        if args.gadget_conf:
            GADGET_CONF_PATH = Path(args.gadget_conf)
            exit_if_not_exist(GADGET_CONF_PATH)
        if args.net:
            APKTOOL_BUILD_OPTS += " -n"
        if args.positional:
            APKTOOL_BUILD_OPTS += f" {args.positional}"

        apk_patch(path=APK_NAME, arch=args.arch, config=GADGET_CONF_PATH, options=APKTOOL_BUILD_OPTS)
        sys.exit(0)
    elif args.pull:
        if not args.package:
            print("Pass the package name")
            print("./apk --pull <apkname.apk> <com.package.name>")
            print("[>] Bye!")
            sys.exit(1)
        PACKAGE_NAME = args.package
        APKTOOL_BUILD_OPTS = ""
        if args.net:
            APKTOOL_BUILD_OPTS += " -n"

        apk_pull(package=PACKAGE_NAME, options=APKTOOL_BUILD_OPTS)
        sys.exit(0)
    elif args.rename:
        APK_NAME = Path(args.rename)
        exit_if_not_exist(APK_NAME)
        if not args.package:
            print("Pass the package name")
            print("./apk --rename <apkname.apk> <com.package.name>")
            print("[>] Bye!")
            sys.exit(1)
        APKTOOL_BUILD_OPTS = ""
        if args.net:
            APKTOOL_BUILD_OPTS += " -n"
        apk_rename(path=APK_NAME, package=args.package, options=APKTOOL_BUILD_OPTS)
        sys.exit(0)
    else:
        print("[!] First arg must be build, decode, pull, rename or patch!")
        print("[>] Bye!")
        sys.exit(1)
