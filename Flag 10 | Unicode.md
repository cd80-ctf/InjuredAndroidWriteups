# Flag 10 | Unicode
Welcome to flag 10! This is a more involved challenge, involving both static and dynamic analysis. If you can complete it, you've got a strong understanding
of the fundamentals of Android exploitation. Let's dive in!

## The target

Launching the InjuredAndroid app and selecting the tenth flag, we see nothing new:

![home_screen](https://user-images.githubusercontent.com/86139991/176229135-90463917-4ad5-46f8-b108-2f751f69bfd9.PNG)

Our goal is to find the password that unlocks the flag.

## First steps

### Reading the manifest

Searching `AndroidManifest.xml` for `"flag_ten"`, we get the usual class `b3nac.injuredandroid.FlagTenUnicodeActivity`:

![manifest](https://user-images.githubusercontent.com/86139991/176229449-4b15b7a7-07db-46d4-ba97-8a2161a65da8.PNG)

The `submitFlag` function for this class is very similar to that of the past two activities:

![submit_flag](https://user-images.githubusercontent.com/86139991/176229634-a2d5d8cc-cd9f-4361-9f3e-2765820e42d9.PNG)

Since this is so similar to past activities that involve Firebase, we should look for the Firebase initialization. 

### Checking the Firebase URL

Whenever an app wants to fetch a value from Firebase, it must create a reference to the child value that it wants.  We can find this in the same place as
before: the class initializer.

![firebase_init](https://user-images.githubusercontent.com/86139991/176229849-714e5f48-8ab8-48c9-b14d-e09895070a71.PNG)

Seems like it's fetching the flag from a child that base64-decodes to `unicode`. Could it really be as easy as going to the child URL at
https://injuredandroid.firebaseio.com/unicode.json?

![firebase_browser](https://user-images.githubusercontent.com/86139991/176230369-31f1ac40-0005-4ef2-aaf4-9fc69b5f877b.PNG)

Sadly not. In order to get the value from Firebase, we'll need to do some dynamic analysis.

### Hooking Firebase with Frida

We are about to pull an extremely useful trick for analyzing any app that uses Firebase. We are going to *hook the function that retrieves values
from Firebase*. This will allow us to see any and every value our app fetches. Whenever you're analyzing an app that uses Firebase, you should think about
setting up this hook, since it lets you see all communication between the app and the database.

The process is similar to our past adventures with Frida. We will install the hook using a simple Python script:

```python
import frida

from time import sleep

def hook():
  device = frida.get_usb_device()  # connect to the Frida server running on the VM
  pid = device.spawn(["b3nac.injuredandroid"])  # start the InjuredAndroid app | note that this leaves the app in a paused state
  
  device.resume(pid)  # allow the app to execute as normal
  time.sleep(1)  # wait for the app to do setup | not doing this breaks the JavaScript injection
  session = device.attach(pid)  # attach our debugger to the app we spawned
  
  with open("flag_10_hook_firebase.js") as f:
    script = session.create_script(f.read())  # read our JavaScript and use it to create a Frida script
    script.load()  # load the script into the target program
    
  input()  # pause and wait for our script to do its work
```

The injected JavaScript looks a little different. In the app we decompiled, the class which fetches values from Firebase is
`com.google.firebase.database.a`, and the fetching function is `a.c()`. Hooking this function looks something like this:


```javascript
Java.perform(function hook_firebase() {  // define a function to be injected into Java code
    console.log("[*] Attempting to hook Firebase...");

    var firebase = Java.use("com.google.firebase.database.a");  // find the class of interest

    decryptor_class.c.overload().implementation = function () { // override the decryption function
        console.log("[+] Reached hooked Firebase function!");

        var fetched_value = this.c(); // call the original function and print the output
        console.log("[!] Value fetched from Firebase: " + fetched_value);

        return fetched_value; // return the original return value
    };
    
    console.log("[+] Hooking successful!");
});

```

If all goes well, when we run the Python script, we should see a status message:

```
[*] Attempting to hook Firebase...
[+] Hooking successful!
```

We can then open the Flag 10 activity and enter a random flag. Lo and behold, *we get the fetched value*!

```
[*] Attempting to hook Firebase...
[+] Hooking successful!
[+] Reached hooked function!
[!] Value fetched from Firebase: John@Github.com
```

### Cheating our way to a victory

In some challenges, we would be done by now. However, there is still another step left to take -- one that requires us to learn about an unusual but
potent method of exploiting string comparisons.

Let's start by taking another look at `submitFlag` to see what actually happens when we submit our guess:

![submit_flag](https://user-images.githubusercontent.com/86139991/176235369-5c0569e4-d573-4395-a88a-693e9f235c85.PNG)

This is similar on the surface to the last two flags. Our input is read, used to create a `b` object, and then passed to a Firebase reference which was
created in the instantiator that we saw earlier. The difference lies in how exactly our input is compared to the value retrieved from Firebase. As it
turns out, this comparison is defined in the `b()` method of the `b` class which contains our input.

Let's take a look at that class, defined in the same file as the main class:

![b_class](https://user-images.githubusercontent.com/86139991/176235825-c8538b32-7989-4b3c-a1fd-b19a173cfca6.PNG)

There's a lot going on here. Let's walk through it one step at a time.

First, the class is instantiated in the first method. A single string is passed to the instantiator, which is stored in `this.f1462b`. Looking back up to
`submitFlag`, we can see that this is our submitted flag. Next, another variable `str2` is defined by calling the `c()` method of a Firebase object.
As we went over in the previous section, this is the method that fetches a value from Firebase. Since we hooked that method with Frida, we already know
its return value: `"John@Github.com"`.

Next, the two strings (our input and the value from Firebase) are compared using the function `g.a()`. We've seen this function several times throughout
the flags, and we know that it's basically a standin for `==`. Thus the first `if` clause compares our input to the Firebase value, and tells us to quit
cheating if they're equal. Very strange...

The strangeness compounds in the next section. Both our input and the Firebase value are uppercased using `str.toUpperCase()`, and then the *uppercased*
strings are compared. If they're equal, we win; if not, we lose. So we need to submit a string that's different to `"John@Github.com"`, but equal to it
when both strings are uppercased.

So what if we try `"john@github.com"`?

![success](https://user-images.githubusercontent.com/86139991/176239647-39532aaa-c2f8-445f-a417-7fd812b62abe.PNG)

Huh. That was easy. And it didn't have anything to do with Unicode. Was that what we were supposed to do?

### What we were supposed to do

As it turns out, even though it works, we were not supposed to sail to victory on the back of case-insensitivity. Rather, we were supposed to exploit a
relatively new and interesting vulnerability that apps encounter when they compare uppercased or lowercased strings -- **Unicode collisions**.

So what is a Unicode collision? The easiest way to tell you is to show you, using the Turkish character `ı`, or *dotless i*:

```java
"i".toUpperCase(); // = "I"
"ı".toUpperCase(); // = "I"
```

That's right -- even though `i` and `ı` are different characters, they are both mapped to `I` by `toUpperCase`. In other words, **`toUpperCase` is not
one-to-one!**

With this in mind, we can achieve the "intended" solution by submitting the value from Firebase, but with `ı` in place of the `i` in "github":

![success](https://user-images.githubusercontent.com/86139991/176239647-39532aaa-c2f8-445f-a417-7fd812b62abe.PNG)

This seemingly strange but harmless bug can have serious consequences. In fact, this exact exploit was used for account takeover on Github, since they
were using `toLowerCase` on their emails when doing a password reset! It's not common, but whenever you suspect strings are being case-normalized, you should
think about trying a Unicode collision.

## The takeaway

So, what did we learn here?

In this challenge, we combined static and dynamic analysis. We learned about a very useful Frida hook which prints out every value that an app fetches
from Firebase, and we exploited Unicode collisions to "win" a string comparison even though the original strings were different.

Next time, we'll take a step back and exploit another common attack surface of Android apps -- **deep links**.
