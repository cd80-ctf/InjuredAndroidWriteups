# Flag 1 | Login
Welcome to the first flag! As with many CTF competitions, this one is fairly straightforward, more focused on teaching you the tools and methods of Android app exploitation than on presenting an intricate puzzle.

## The target

Launching the InjuredAndroid app and selecting the first flag, we are greeted with a basic login prompt:

![login](https://user-images.githubusercontent.com/86139991/173711606-a19d0b23-5ea1-489b-924b-f77ea60f826e.PNG)

The only real thing we have to go on is that we're looking for a password. Let's jump into the decompiled app and see what this login page is actually doing.

## The process

### Reading the manifest

The first place to look when analyzing any Android application is the manifest. Stored in `AndroidManifest.xml`, this document provides an outline
of everything the application does: what permissions it requires, what activities (read: classes) it implements, and the rules and settings regarding
who can access them. Suffice to say, if you're trying to find vulnerabilities in an Android app, start by looking at `AndroidManifest.xml`.

We can get at the manifest using the Jadx decompiler. Simply opening `InjuredAndroid.apk` in Jadx gives us a full breakdown of every class and resource
in the application:

![jadx](https://user-images.githubusercontent.com/86139991/173711393-06672881-24c5-411f-bf7d-d0ec365d7ef3.PNG)

The manifest can always be found in the top-level `resources` folder:

![manifest](https://user-images.githubusercontent.com/86139991/173711486-714e17bc-0fc9-4f42-b80e-434cf3f58bf3.PNG)

If you've never looked at an Android manifest before, this may seem overwhelming. Don't worry! We're only interested in a very small section of this,
and we won't have a hard time finding it.

### Finding the relevant activity

Recall that our goal is to figure out what the `Flag 1 | Login` page is doing. Searching the manifest for strings like `flag_1` and `flag_one`, we quickly
find something that looks promising:

![flag_one_in_manifest](https://user-images.githubusercontent.com/86139991/173711982-c315d057-c0b8-46b8-9e96-1965ae54d867.PNG)

This line declares an `activity`. Activities are the atomic unit of an Android app; every screen, popup, and basic functionality of an app has an associated
`activity` declared in the manifest. In this case, this seems to be the `activity` that handles the `Flag 1` screen and login form that we're trying
to crack, so we should definitely look at it.

Recall that we want to find the code which handles the `Flag 1` event. The actual code associated with an `activity` starts with the class declared in the XML
field `android:name`. In our case, the class of interest is `b3nac.injuredandroid.FlagOneLoginActivity`.

### Reading the decompiled class

We can find the decompiled source for this class in Jadx, in the eponymous folder under `Source Code`:

![source_code](https://user-images.githubusercontent.com/86139991/173713582-a0f0a273-9a83-4bce-849c-a0f95297a232.PNG)

Immediately, the function `submitFlag` should catch our eye:

![submit_flag](https://user-images.githubusercontent.com/86139991/173713786-19383d26-b3c4-4817-a64f-c49f0b4fa4e0.PNG)

Besides some inexplicably missing deobfuscation, it shouldn't take a genius to figure out what this function is doing. We presumably get a string from
some object associated with `"editText2"` and compare it to `"F1ag_0n3"`. If they match, we do something involving FlagOneSuccess.

Let's see what happens when we plug that string into the app:

![success](https://user-images.githubusercontent.com/86139991/173714087-1cb44d01-4180-4d7c-9cd3-cc9877801597.PNG)

Bingo.

## The takeaway

So, what did we learn here?

In this challenge, we learned the basics of how an Android app is structured. We used the `AndroidManifest.xml` to find a class that we wanted to inspect,
examined the decompiled source code of that class, and used that information to submit the winning flag.

This may seem like a trivial exercise, but it's really not: by completing it, we've proven that we know the fundamental skills necessary to attack
an Android application. Next time, we'll learn another key skill and make use of our debugger.
