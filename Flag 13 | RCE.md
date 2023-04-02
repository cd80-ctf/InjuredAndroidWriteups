# Flag 13 | RCE
After making a malicious app in the last activity, we deserve a break. This challenge is a bit smaller than the previous one, and mostly serves
to introduce another new concept -- dealing with **custom binaries in assets**.

## The target

Launching the InjuredAndroid app and selecting the thirteenth challenge, we find absolutely nothing:

![home_screen](https://user-images.githubusercontent.com/86139991/176735177-280d7e18-4c66-42ad-96d4-be9e2280b3ea.PNG)

Time to hunt for exported activities and deep links!

## Exploitation

### Reading the manifest

Searching `AndroidManifest.xml` for `"flag_thirteen"` gives us nothing. We're used to this by now, though, and searching for the keyword `rce` gives us
a very promising class:

![manifest](https://user-images.githubusercontent.com/86139991/176735676-8f8c1e80-a38f-4514-809d-b25d2b7b9352.PNG)

If you've followed the past few flags, you know exactly what this is. This flag has a deeplink associated with it! This time, in addition to requiring
a scheme of `android:scheme=flag13`, the deeplink requires a host `android:host=rce`. In order to reach this activity, we must therefore invoke a deep link
of the form `flag13://rce`.

To figure out what exactly this deeplink can do, let's hop over to the associated class, `b3nac.injuredandroid.RCEActivity`:

### Analyzing the class

The class for this challenge is quite a bit larger than the past ones. However, as with any deep link activity, we should start by looking at `onCreate`:

![on_create](https://user-images.githubusercontent.com/86139991/176736931-27b03ea1-45df-4725-b145-a9d457e80919.PNG)

Okay. Stop.

If you ever -- and I mean **ever** see an activity, accessible from the outside, which calls `runtime.exec` with user-provided input, you need to drop
everything. This is arguably the *worst* vulnerability that *any* application can have. This app, if we read it correctly,

- extracts user-provided parameters `binary, param`, and `combined` from a deep link,
- calls a function that compares the `combined` parameter to a Firebase value if it exists,
- an if it doesn't, **sticks `binary` and `param` into a string and calls `runtime.exec` on it.**

In other words, this app calls a shell command for us. Furthermore, the app then captures the command's output and shows it to us in a `textView`.

### It's Worse Than it Looks

In fact, this app is more broken than it intends to be. To solve the flag, all you need to do is run some executables that are copied into the `/files`
directory. This is why the app puts this directory at the start of our command. However, **the app fails to filter our input for two things**:

- Shell metacharacters, such as `$()`, `|`, and `{}`. These characters allow us to embed extra commands in a single command. For example, if we pass
`test | restart` as our binary, the command run will be `/files/test | restart`, which will restart the device.
- Path traversal via `..`. This means we don't even need shell metacharacters; we can execute any binary on the system. For example, if our binary is
`../../../../../../../cat /etc/passwd`, the command will be `/files/../../../../../../../cat /etc/passwd`, which will print the contents of `/etc/passwd`.

Whenever you find a potentially vulnerable `exec` call, always remember to check for shell metacharacters and path traversal. If you can find just one,
then any malicious app can take full control of the device.

### The intended solution

We have already discussed the main vulnerability of this app. However, solving the flag requires no advanced techniques -- all we need to do is run some
binaries the app provides for us in the `/files/` directory.

Let's fire up `adb shell` and check this directory. Recall that every app stores its data in the home directory `/data/data/APPNAME`, so `/files` is actually
located at `/data/data/APPNAME/files` on the filesystem:

![files](https://user-images.githubusercontent.com/86139991/176743909-c1759fd1-b4cd-4b45-b7c7-15219b408903.png)

Seems like we've got some options. However, not all of these files are necessarily executables. We can determine (or at least guess with good accuracy)
what each file actually is with the helpful `file` command:

![file_results](https://user-images.githubusercontent.com/86139991/176744287-e8c97979-507b-4d16-b720-a17b76e64616.PNG)

Out of four files, we have three executables. One of them, `narnia.arm64`, is an ARM executable, which won't run on our `x86_64` system. This leaves us
with two options: `menu` and `narnia.x86_64`. 

Of the two possibilities, `narnia` seems the most important, since versions were included for multiple architectures. Let's run it and see what happens:

![execution_failed](https://user-images.githubusercontent.com/86139991/176745367-72075e88-3655-4a87-943d-ea7e329cb594.PNG)

Whoops -- forgot to change permissions. Doing so with `chmod +x narnia.x86_64` and trying again:

![execution_1](https://user-images.githubusercontent.com/86139991/176746850-e68c55ed-da26-4e5d-a20c-3c1662be8361.PNG)

Okay... what if we run it with `--help`?

![execution_2](https://user-images.githubusercontent.com/86139991/176746981-e534e248-ddff-48b9-afa6-d64e25029cc0.PNG)

Running all these commands:

![execution_3](https://user-images.githubusercontent.com/86139991/176748296-7fdb9b50-3087-4175-bf9c-637b613fdd98.PNG)

We got rick rolled, a potato, and what seems to be three parts of a flag. 

### Putting it together

Recall that the `onCreate` function checks the deep link that called it for a `combined` parameter. If it finds one, it calls what we now recognize is
a Firebase check on this parameter. Let's see what happens when we run the usual deep link command using ADB:

```
adb shell am start -a android.intent.action.VIEW -d "flag13://rce?combined=Treasure_Planet"
```

![success](https://user-images.githubusercontent.com/86139991/176749229-8635eedd-e0b4-46b4-92f9-37635856889a.PNG)

Nice.

## The takeaway

So, what did we learn here?

To be honest, the largest takeaway from this challenge was not how we got the flag. Rather, the most important lesson was how to identify a command injection
vulnerability in an Android app. We found an exposed activity (via a deeplink) which puts unfiltered user command into an `exec` call. If you find this
even once in your bug-hunting career, you've essentially struck gold.

Next time, we'll dip our toes into another field of bug hunting and do some **binary analysis**.
