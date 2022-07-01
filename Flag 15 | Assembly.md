# Flag 15 | Assembly
Welcome to the last challenge! (There are other challenges listed on the app, but none of them seem to work on my emulator.)
This is a fun interdisciplinary challenge that teaches not just Android app exploitation, but binary exploitation as well. Let's get into it!

## The target

Launching the InjuredAndroid app and selecting the fifteenth challenge, we see the usual input:

![home_screen](https://user-images.githubusercontent.com/86139991/176894172-34a410f2-8c66-4f38-abb9-58fd554c047e.PNG)

Let's hop into the source code!

## Exploitation

### Reading the manifest

Since searching for `"flag_xxx"` hasn't been useful for the past few activities, let's search for what's in the top bar of the in-app activity,
`AssemblyActivity`:

![manifest](https://user-images.githubusercontent.com/86139991/176894937-8b8ec8d4-8c07-4ac6-80b5-c20b6f533acf.PNG)

Diving into this class, we find something very interesting while looking for the `submitFlag` function:

![native_function](https://user-images.githubusercontent.com/86139991/176895459-6ef1b4a2-c636-4175-b608-3444c9899ade.PNG)

The `native` flag is one of the most fascinating features of Java. Whenever you see it, it's worth looking further into. Essentially, this means that
the function `stringFromJNI` is *not written in Java*, but written in *native code* (i.e. compiled C or C++) and then *imported* into Java. Native code
is interesting from an exploitation standpoint because it's prone to several classic memory corruption vulnerabilities, such as buffer overflows.
Also, since this is the only interesting function in the entire class, it's probably where the flag is.

### Finding the native library

In order to find the flag, we probably want to look at the source of the native function `stringFromJNI()`. So, how can we do that?

When you see a `native` function, you will always find a call to `System.loadLibrary` somewhere nearby. This is a very special function that can load 
compiled code (as a `.so` file). In this case, we find it in the middle of the class:

![system_loadlibrary](https://user-images.githubusercontent.com/86139991/176896494-bc563972-38c8-4be9-8524-61457e462570.PNG)

(Note that `System.loadLibrary` calls are also a powerful exploitation tool. If we can find a vulnerability in an app that lets us write arbitrary files,
overwriting a loaded `.so` file is a quick and easy way to get command execution on the phone.)

Since this is the only loaded library, the native function must be implemented in `native-lib.so`. So where can we find that?

Unless otherwise specified, shared object files in Android are stored in the application's `lib`. We can access these by going back to the very first thing
we downloaded when we embarked on this journey: the InjuredAndroid `.apk` file.

If you spend time looking into file formats, you will learn that a surprising number of "unique" file formats are actually `zip` files with different
extensions. APK files are examples of this. In fact, if you rename the `InjuredAndroid.apk` file to `InjuredAndroid.zip`, you can extract it like a regular
`zip` file!

Once you've extracted the APK file to another folder, you should see something like this:

![extracted_directory](https://user-images.githubusercontent.com/86139991/176898842-f6fa6837-fb05-42af-b37d-25a2c7ff6e36.PNG)

Now we can simply browse the `lib` directory under our architecture (in this case, `x86_64`) to find our `.so` file:

![so_file](https://user-images.githubusercontent.com/86139991/176899673-56b77667-15b1-417d-835e-644dfb0ca92c.PNG)

Great -- we've found our compiled code. Now, what the hell do we do with it?

### Decompiling the .so with Ghidra

Recall how we started diving into Android app code in the first place. In order to figure out what the app was doing, we needed a decompiler that turned
the packaged app into readable Java code. In our case, we used Jadx. Now we face a similar situation: we have some compiled native code, and we need
to figure out what it does. For this, we need a native code decompiler.

There are many options for this. Some popular choices include BinaryNinja, IDA Community, and Ghidra. For this writeup, we will use Ghidra, for a couple
reasons:

- It's completely free (or rather, already paid for by your tax dollars if you're an American)
- It's multi-platform
- It has a high-quality, built-in decompiler

You can download Ghidra by going to https://ghidra-sre.org/ and following the instructions. When you launch it for the first time, you should see something
like this:

![ghidra_empty](https://user-images.githubusercontent.com/86139991/176902127-1af7c5e9-e134-4332-af93-5e10154fb391.PNG)

Let's create a project. Go to `File -> New Project` and create a non-shared project called InjuredAndroid. Once we've done this, we get a similar screen:

![ghidra_new_project](https://user-images.githubusercontent.com/86139991/176902432-1b58ea8f-97d6-4619-80f6-bb4999772a75.PNG)

We can now import the `.so` file we're interested in (`libnative-lib.so`) by dragging and dropping it into this window. Ghidra will process the file and
display some information about it. After that's done, we can jump into the real fun: decompiling this shared library. This can be done simply by
double-clicking on the new file. 

Once the file opens, Ghidra will ask you if you want to analyze it. I honestly have no idea why this check exists. Hit `Yes` and let the decompiler do its
magic.

When the decompiler is done, we can start delving into the file in earnest. Recall that we want to find the source code for some function that is exported
to the Java function `stringFromJNI`. The intuitive starting place for this search is the `Functions` list in the sidebar:

![sidebar_functions](https://user-images.githubusercontent.com/86139991/176903329-5e49f319-69a6-498b-869c-500deb1c62ab.PNG)

Opening this list can be overwhelming. Luckily, for a first pass, there's no need to delve deep into it. Let's just scroll down the list and see if we find
anything obviously interesting.

About halfway down, a VERY interesting function catches our eye:

![interesting_function](https://user-images.githubusercontent.com/86139991/176903626-87222feb-3d04-4e80-8cad-d32d2b75df73.PNG)

Looks like they made it easy for us. Let's click on the function to open it in the decompiler:

![decompiled_function](https://user-images.githubusercontent.com/86139991/176903770-fb769b7f-3dbe-45be-825e-a88b0ae1ceea.PNG)

Again, there's a lot going on here, so let's just skim and look for something interesting. Right away, we can see a C++ string being defined on lines
20 and 21. This string seems to be set to "win". There's no way this can be the flag, right?

![success](https://user-images.githubusercontent.com/86139991/176904115-7f1b0323-d38a-4294-ab3f-918e4255a41a.PNG)

Huh. Nice?

## The takeaway

So, what did we learn here?

In this final activity, we learned how Java can interface with compiled code through `native` variables and functions. We tracked down the `.so` file that
was used to load a native function via `System.loadLibrary`, decompiled it with Ghidra, and intensively studied the decompiled source of the imported
function to find the flag. We also noted that loading native code is an exploit tool that can be used to turn arbitrary file write into arbitrary code
execution.

If you've gotten this far, congratulations! You've learned almost all you need to get started in Android bug bounty hunting. If you want to continue learning
in a structured environment, a good second step is the [Oversecured example application](https://github.com/oversecured/ovaa). This app assumes some prior
knowledge about Android app analysis (which you now have) and features several vulnerabilities that are much more similar to ones you'd see in the wild.
I hope to do a writeup on this app sooner or later. Or you may wish to grab some APKs from the app store and dive right in. Either way, good luck and
happy hunting!
