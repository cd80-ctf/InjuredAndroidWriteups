# Flag 7 | Sqlite
Welcome back. Last time, we made our first daliance into using both static analysis (reading source code) and dynamic analysis (debugging with Frida).
This time, we'll delve into another example, this time with a twist -- local SQL databases.

## The target

Launching the InjuredAndroid app and selecting the seventh flag, we find that this challenge takes two inputs:

![home_screen](https://user-images.githubusercontent.com/86139991/175838399-0571072c-9899-4acd-9b8e-381080b302ee.PNG)

## First steps

### Reading the manifest

Searching `AndroidManifest.xml` for `"flag_seven"` gives us the class `b3nac.injuredandroid.FlagSevenSqliteActivity`:

![manifest](https://user-images.githubusercontent.com/86139991/175838424-4e873593-cc4b-4c36-8074-36aa07ef6d25.PNG)

Checking this class in the decompiler, we find our usual `submitFlag` function:

![submit_flag](https://user-images.githubusercontent.com/86139991/175839432-d8ca279b-28c8-4f8d-8153-8514b0866948.PNG)

(note that we have renamed some variables in the decompiler, so yours might look different)

As before, our input strings are being compared to values that are pulled from some class. In this case, the class is `b3nac.injuredandroid.j`. Let's
check it out:

![j_class](https://user-images.githubusercontent.com/86139991/175839822-643606e3-2092-4ffa-858e-8ee70f02c4fb.PNG)

This looks similar to Flag 6 -- the desired flag and password are kept in some encrypted storage. This time, however, the encryption used is AES256,
which is far beyond brute-forcable.

We now have a choice -- repeat our process from Flag 6 and hook the decryption functions using Frida, or try to find the password and flag some other way.

## Static Analysis

We'll start with the way the flag is "meant" to be solved. Doing so will teach us valuable information about where apps store persistent information --
specifically, their databases.

### Finding the database

First, let's re-examine the main class. In the `onCreate` function, the app appears to write several base64-decoded values into a database:

![on_create](https://user-images.githubusercontent.com/86139991/176036521-038b2d2b-d185-42ef-954e-de8b5e1c0398.PNG)

Of course, we could base64 decode these values ourselves, but we already know how to do that. Let's play along with the level and try to find the database
where the decoded values are stored.

By default, an Android app stores its persistent data in the folder `/data/data/APPNAME`. Let's get a shell on our device by running `adb shell` and
check out this directory:

![adb_shell](https://user-images.githubusercontent.com/86139991/176037384-43a9ff3a-d685-4185-970e-d88bd135ebb9.png)

Just as we hoped, there's a `databases` folder. The sole database, `Thisisatest`, seems to be the one created in the `onCreate` function. We're on
the right path.

(If you aren't finding the database, note that the `onDestroy` method of the class actually deletes the database, so make sure the activity is open
when you try to access it).

### Dumping the database and decoding the data

Let's use `sqlite` to look inside the database:

![sqlite_dump](https://user-images.githubusercontent.com/86139991/176037712-9a7eac88-f976-49e6-9475-199e060140ec.PNG)

Hmm. Looks like the flag and password are still obfuscated. Luckily, they aren't obfuscated very well!

Let's start with the flag. The database says the flag value is a hash, but even if it didn't, we would be well advised to throw it into a hash cracker
or three. Many things that need to be stored are hashed, and many common hashes can be cracked very easily. A good first-pass hash cracker is
https://crackstation.net/. Let's submit the flag hash and see what we get:

![crackstation](https://user-images.githubusercontent.com/86139991/176039114-6c7232c5-5a6c-41dc-8692-e420cf41b421.PNG)

As expected, this is a weak unsalted hash of a known value, and therefore little better than storing values in plaintext. One of two down!

Having cracked the flag, we might suspect that the password is also a hash. Unfortunately, throwing this at our hash cracker doesn't give us anything.
This doesn't necessarily mean it's not hashed (it may be salted or just an uncommon value), but it means we should consider other possibilities.

If you haven't done many capture-the-flag competitions before, you may be forgiven for getting frustrated on this point. Most obfuscated values you'll see
in the wild are either hashed or encrypted using a common algorithm like AES. This password is not. Instead, it is encoded using a format that is common
in hobbyist competitions but almost unused in the real world. For these reasons, I wouldn't condemn anyone for looking up this answer.

However, there are some hints that this is encrypted with a rudimentary algorithm. Specifically, let's look at the first several characters of the encrypted
password:

```
9EEADi^^
```

It's a bit of a stretch, but an observant hacker might notice that this has a similar "structure" to

```
https://
```

Whenever you notice things like this, especially in amatuer competitions, you should consider the possibility that the value is ROT-encrypted. ROT encryption,
sometimes known as Caesar ciphers, is when every character in a string is replaced with one a set number of steps down in the alphabet (or in this case,
the ASCII table). This is a horrible form of encryption -- after all, there are only 255 possible keys. Therefore if you suspect a value might be
ROT-encrypted, it doesn't hurt to throw it at a tool that tries all possible rotations. 

In our case, the process is simpler because we suspect that the value is a `https` link. This means that the shift between the first character (`9`) and `h`
should be the shift of the whole string. One can check an ASCII table to determine that this shift is 47, meaning the whole string is probably encrypted
using ROT47. Throwing this into an online tool for ROT47 (https://www.browserling.com/tools/rot47), our suspcions are confirmed and we get a link:

```
https://injuredandroid.firebaseio.com/sqlite.json
```

Going to this link, we find the password:

![password](https://user-images.githubusercontent.com/86139991/176041729-a8a28e70-6a6d-4068-b13f-d7a9e8cf295e.PNG)

Plugging the flag and password we deobfuscated into the app:

![success](https://user-images.githubusercontent.com/86139991/176041878-2be2d5a4-26e4-4bc7-91c0-587c53b9b65f.PNG)

Nice.

(The experienced among you may have found another way to get at these values. We'll look at that in the next flag).

## Dynamic Analysis

As is often the case, when dynamic analysis is possible, it's faster. Solving this flag with dynamic analysis requires nothing more than a basic modification
of our Frida script from the last flag. Just as before, we'll find the decryption function, hook it, and print the output.

I'll assume you have Frida set up in accordance with the previous flag. If you haven't, refer to that writeup for instructions.

### Fixing a common error

During this writeup, I ran into an issue with the Frida server. My Python script refused to connect to the device, but restarting the server via `adb shell`
told me that the server was already running. If you have this issue too, here's the simple fix I worked out:

1. On your host machine, run `frida-ps -U | grep server`.
2. Check the output for a line of the form `frida-server-xx.x.x` and note the PID.
3. Kill the server on the emulator with `adb shell "kill PID"`, where PID is the PID you found in the last step.
4. Finally, restart the server with `adb shell "/data/local/tmp/frida_server &`, or whatever you named your binary.

### Hooking the decryption method

As before, our Frida analysis consists of two parts: a Python script that connects to the Frida server, and a JavaScript script that injects code into the
process. The Python half of the equation should look something like this:

```python
import frida

from time import sleep

def hook():
  device = frida.get_usb_device()  # connect to the Frida server running on the VM
  pid = device.spawn(["b3nac.injuredandroid"])  # start the InjuredAndroid app | note that this leaves the app in a paused state
  
  device.resume(pid)  # allow the app to execute as normal
  time.sleep(1)  # wait for the app to do setup | not doing this breaks the JavaScript injection
  session = device.attach(pid)  # attach our debugger to the app we spawned
  
  with open("flag_7_decrypt_hook.js") as f:
    script = session.create_script(f.read())  # read our JavaScript and use it to create a Frida script
    script.load()  # load the script into the target program
    
  input()  # pause and wait for our script to do its work
```

To write the injected Java, we need to note the decryption method and the class that runs it. In our case, the `b3nac.injuredandroid.j` class we found earlier
does the decrypting, and the method `j.c()` returns the actual value. With this in mind, we can hook it just like we did last time:

```javascript
Java.perform(function hook_decrypt() {  // define a function to be injected into Java code
    console.log("[+] Hooking successful!");
    var decryptor_class = Java.use("b3nac.injuredandroid.j");  // find the class of interest
    var String = Java.use("java.lang.String");

    decryptor_class.a.overload("java.lang.String", "java.lang.String").implementation = function (str1, str2) { // override the decryption function
        console.log("[+] Reached hooked decrypt() function!");
        console.log("[*] Getting string " + str1 + "...");

        var decrypted_arg = this.c(str1, str2); // call the original function on the passed values and store the result
        console.log("[!] Decrypted value: " + decrypted_arg); // print the decrypted return value

        return decrypted_arg; // return the decrypted value so the program continues as normal
});

```

When we run the Python script, we should see a status message:

```
[+] Hooking successful!
```

We can now open the Flag 7 activity and enter some random data:

![frida_results](https://user-images.githubusercontent.com/86139991/176043461-1dfe26ea-c41f-43b9-bad0-1ce6ee60d3ba.PNG)

Entering these values...

![success](https://user-images.githubusercontent.com/86139991/176043483-71f63106-0874-4bbc-a373-b264a6828758.PNG)

Very nice.

## The takeaway

So, what did we learn here?

In this challenge, we delved into where Android apps store their persistent data. We used an `adb` shell to view an `sqlite` database and retrieve
sensitive information. We also refreshed ourselves on dynamic analysis and function hooking with Frida.

The astute reader who's done Android app analysis before might have noticed that we missed an easy way to solve this flag. In the next flag, we'll look at
exactly that.
