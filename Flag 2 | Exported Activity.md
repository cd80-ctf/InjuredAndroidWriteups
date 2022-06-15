# Flag 2 | Exported Activity
Welcome back! Last time, we were introduced to the basics of what makes an Android app tick, and where to look if we want to break it (mostly `AndroidManifest.xml`).
We were also introduced to the concept of activities. This time, we're going to learn about the most important attack surface that any Android app can present:
its *exported activities*.

## The target

Launching the InjuredAndroid app and selecting the second flag, we find a surprise:

![nothing](https://user-images.githubusercontent.com/86139991/173715295-4e03bda2-bb69-4071-b3a7-6ecc30432f2b.PNG)

That's right: nothing! No buttons, no prompts, not even a place to input the flag. All we have is a mysterious statement that we can invoke activities
without going directly through the app. Hmm...

## The process

### Reading the manifest

As always, we will start off by reading `AndroidManifest.xml`. Since we're attacking the second flag, and since we found the activity for the first flag
under `flag_one`, let's search the manifest for `flag_two`:

![activity](https://user-images.githubusercontent.com/86139991/173715887-4126b8d9-3d94-4acf-a2fa-a0a7003a808f.PNG)

Looks like the first relevant class is `b3nac.injuredandroid.FlagTwoAction`. Let's take a look at it in the decompiler:

![activity_source_code](https://user-images.githubusercontent.com/86139991/173716005-405958a2-6cf5-4239-98f3-1663953ab0c0.PNG)

Unlike last time, there's nothing immediately obvious here; just some rendering logic and an `onClick` handler for the hint button. The plot thickens.

Let's cut to the chase. Both the name of the flag and the hints in the decompiled code seem to be telling us that we can somehow access flag 2 from a
different activity -- one that is somehow `exported`.

### Exported activities: the evergreen attack surface

I mentioned before that when you're attacking an Android application, the first place to look is `AndroidManifest.xml`. We can now learn the second part
of this rule: when looking at `AndroidManifest.xml`, the first thing to look for is exported activities.

Exported activities are exactly what they sound like. Unlike normal activities, which can only be launched by the app which declares them,
an exported activity can be launched by **any application on your phone**. That is, if you have an evil app on the same phone as a vulnerable app,
and the vulnerable app has an exported activity, your evil app can execute that activity.

Your first instinct might be to wonder why anyone would ever want this. The truth is, you probably appreciate this behavior on a daily basis. Whenever you
click on an email address and it opens your email client, whenever you click on a Google Docs link and it opens in the app, you are seeing an exported
action at work. The ability for different apps to communicate and work together is a huge part of the mobile experience. This is great news for us
as attackers: it means we will never lack for attack surface.

But enough of the philosophizing. How do we find these exported events?

### Looking through exported activities

It's as simple as one search in `AndroidManifest.xml`. All exported events are marked with `android:exported="true"`. Let's search for this string
and see what we find.

The first hit, starting from the top, is the activity associated to the class `FlagEighteenActivity`. This will be interesting later. 
The second hit is for an activity associated to `b3nac.injuredandroid.ExportedProtectedIntent`. That sounds more fruitful. Let's look at the class:

![exported_protected_intent](https://user-images.githubusercontent.com/86139991/173718298-f7ee456d-2c17-41db-866e-c215ba77d456.PNG)

Hmm. This looks interesting, but doesn't have any references to Flag 2 or anything. Let's keep it in our back pocket for now and keep looking.

The next exported activity we find is linked to the enigmatic class `b3nac.injuredandroid.QXV0aA`. Again, a glance at the source code reveals 
some interesting stuff, but no references to Flag 2. Let's table this class as well.

Next, we find another mysterious activity linked to `b3nac.injuredandroid.b25lActivity`. Let's look at the source:

![b25l_activity](https://user-images.githubusercontent.com/86139991/173718915-f84973a3-56ad-46d9-8bf9-d4f53fd88785.PNG)

Jackpot! Not only does this directly mention Flag 2, it seems to be unlocking it in the `onCreate` event. This means we don't have to do anything other
than invoke the activity, and the app will unlock the flag for us.

There's just one question left: how do we call this activity?

### Calling exported activities from ADB

In a real scenario, we would call a vulnerable exported event from a malicious app on the same phone. In our lab scenario, however, there's a much easier
way to do it: use the Android Debug Bridge (ADB).

If you've been following since the setup, you should have already started the ADB backend on your computer. If not, please refer to that section of 
[the README](https://github.com/cd80-ctf/InjuredAndroidWriteups). Note that if you have to bring the backend up again, you should restart your emulator
so that it connects to the backend currently running on your computer.

If the ADB backend is running, you've done the hard part. Now all we need to do is call the exported activity from ADB. 

Let's take a closer look at the XML declaration of the exported activity:

```
<activity android:name="b3nac.injuredandroid.b25lActivity" android:exported="true"/>
```

A quick Google search gives us a one-liner that runs this activity from ADB. The command looks like this

```
adb shell am start -n PACKAGENAME/.ACTIVITY 
```

where

- `adb shell` is running an ADB shell command, 
- `am` stands for Activity Manager, 
- `start -n` tells ADB to start a new activity, 
- `PACKAGENAME` is the name of the package containing the activity (in our case, we see from the decompiler that this is `b3nac.injuredandroid`)
- `ACTIVITY` is the name of the exported activity (`b25lActivity`)

Substituting in our package name and activity and giving it a go:

![shell_command](https://user-images.githubusercontent.com/86139991/173720321-c54b6ec9-756c-46cd-bc5e-8506d49a31e3.png)

Let's check back in with our emulator:

![success](https://user-images.githubusercontent.com/86139991/173720351-e2503032-4551-4db5-a509-6745bcb4d0a7.PNG)

Bingo! We successfully called the activity without even touching the vulnerable application!

## The takeaway

So, what did we learn here?

In this challenge, we learned about the easiest attack surface of an Android application: its exported activities. These are activities defined in
`AndroidManifest.xml` with the tag `android:exported="true"`, and they can be invoked by *any* application on the phone. This makes them incredibly
easy to exploit. We found a vulnerable exported activity in our decompiler, then called it from the command line with ADB.

This flag taught us about the first thing we should look at when auditing a vulnerable application. Next time, we'll look at possibly the second thing:
the application's resources.
