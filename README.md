# InjuredAndroidWriteups
Writeups for the intentionally vulnerable Android app InjuredAndroid (https://github.com/B3nac/InjuredAndroid)

# Setup

As every researcher knows, the most difficult part of exploiting a target application or device is often setting it up in the first place. As such, I'll give a detailed walkthrough of how to set up your Android research environment.

## The vulnerable VM

### Android Studio
To exploit an Android app, we need an Android device. However, that costs money. To avoid this complication, we will use the Android emulator provided by
Google as part of their Android Studio IDE. There are [ways](https://medium.com/michael-wallace/how-to-install-android-sdk-and-setup-avd-emulator-without-android-studio-aeb55c014264) of setting up this emulator without Android Studio, but it's more convenient to use what Google gave us. In that spirit:

- [Download Android Studio](https://developer.android.com/studio) from the official source

### Creating an image
Once Android Studio is set up, it's time to create the actual VM. Thankfully, this is fairly easy:

1. In Android Studio, create a blank project. We won't be using this; we just need it to access the device manager.
2. Once you've created the project, open the Device Manager by clicking the well-hidden tab on the right:
![device_manager](https://user-images.githubusercontent.com/86139991/173696892-8b0c2ec1-7f00-4d7e-b314-7b1ea38888dd.png)
3. Select any phone device -- it shouldn't matter which.
4. On the System Images page, make sure to go to the `x86` tab and choose an image with Google APIs. This will be invaluable in our future efforts:
![system_images](https://user-images.githubusercontent.com/86139991/173699399-57add92f-2b0b-4ed6-8531-c9e88db1382b.png)
5. Click `Finish` to create your Android image.

Before we close Android Studio, let's increase the storage of the device. This will be useful later when we want to run debug servers or other
nonsense on the VM:

1. In Device Manager, click the pen icon to edit your image.
2. Click "Show Advanced Settings" and scroll to the bottom.
3. Set the Internal Storage to 2048 MB.

### Running the image
Once we create the image, we're all done with Android Studio. We can now run the VM we created using the `emulator` binary that it installed on our system. At time of writing, this can be in a few different places based on your operating system:

- On Windows 10, the emulator is located in `C:\Users\USERNAME\AppData\Local\Android\Sdk\emulator`
- On Mac, the emulator is in `/Users/janedoe/Library/Android/sdk/emulator/emulator`
- On Ubuntu and similar distributions, it's in `~/Android/Sdk/emulator`

If you wish, it could be convenient to add this directory to your `PATH`. Once you've done this, or from the folder containing the emulator, you can list your images by running

`emulator -list-avds`

If you've never used Android Studio before, there should be one image -- the one you just created. Now we can start that image with

`emulator -avd AVDNAME -netdelay none -netspeed full`

With any luck, an emulated phone screen should appear. Hit the power button and give it a couple seconds, and congratulations -- you're emulating Android for free!

## Installing a debugger

If you've gotten the VM running, you're already past the hard part. However, there are two more useful tools we need to set up. First and foremost is ADB, the premiere Android application debugger, which we will use to help us get nearly every flag.

You can download ADB for
- [Windows](https://dl.google.com/android/repository/platform-tools-latest-windows.zip)
- [Mac](https://dl.google.com/android/repository/platform-tools-latest-darwin.zip)
- [Linux](https://dl.google.com/android/repository/platform-tools-latest-linux.zip)

Download and extract the binary. Once you've done that, you might want to add the directory containing `adb` to your PATH as well. Finally, run

`adb start-server`

in the command line to start the ADB backend. In order to avoid permissions errors, we should also make sure it's running as root:

`adb root`

If you'd like, you can now restart your Android VM. Doing so will connect it to your ADB backend automatically, allowing you to debug nearly everything on the phone.

## Installing a decompiler

We're almost ready to go hunting for vulns. Our last step is to download a .apk unpacker and decompiler -- an app that lets us read through the decompiled Java code that went into an Android application.

The canonical Android unpacker and decompiler is [Jadx](https://github.com/skylot/jadx/releases/tag/v1.4.1). You can download it for

- Windows via the [latest GitHub release](https://github.com/skylot/jadx/releases/tag/v1.4.1)
- Mac with `brew install jadx`
- Linux with `sudo apt install jadx`

You can now start Jadx by running `jadx` on Mac or Linux, or the `bin/jadx-gui.bat` script on Windows.

## All done!

Congratulations! If you've gotten to this point, you're ready to start searching for Android application vulnerabilities. Happy hunting!
