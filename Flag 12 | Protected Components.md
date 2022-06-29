# Flag 12 | Protected Components
It's time to get realistic. In the real world, vulnerabilities in Android apps are exploited not by finding a flag or running commands in ADB, but by
a malicious app running on the same phone. In this challenge, we'll write our first minimal Android app to exploit an exported activity.

## The target

Launching the InjuredAndroid app and selecting the twelfth flag, we again find that we cannot open this challenge manually:

![home_screen](https://user-images.githubusercontent.com/86139991/176257017-eb5efc0c-2f0d-4ce6-a817-e5f4ddc75b9e.PNG)

Just like last time, this means we should start looking for an exported activity.

## Exploitation

### Reading the manifest

Unlike last time, searching `AndroidManifest.xml` for `"flag_twelve"` gives us a class: (`b3nac.injuredandroid.FlagTwelveProtectedActivity`)

![manifest_1](https://user-images.githubusercontent.com/86139991/176508959-5cbcc261-bf77-4f06-80c3-00117466cd61.PNG)

However, the structure of this class is strange. There's no `submitFlag` function! In fact, there is only one function, `onCreate`, which seems to deal
with intents:

![main_class](https://user-images.githubusercontent.com/86139991/176519325-3cf22a1c-61ec-4cdf-93e6-90ba1f554baf.PNG)

This is strange. The `onCreate` method is parsing a URI, which would usually imply that it was invoked via a deep link... but there's no deep link
in the manifest!

### Protected activities and hubs

Whenever you see something like this -- a class that parses an intent but isn't exposed in the manifest -- you are likely looking at a
**protected activity**. These are quite common in Android apps. The logic goes like this: instead of exporting every activity that might be used
by an external app, it's better to export **just one** "hub" activity that can call the other "public" activities. This adds security, because the one exported
activity can perform checks to make sure an external app is allowed to access an activity. Protected activities are common enough that, whenever you look
at an exported activity, the first thing you check should be whether it can call other activities. Checking for protected activities will do wonders for your
attack surface.

With protected activities in mind, let's check the manifest for exported activites that might call `FlagTwelveProtectedActivity`. As usual, we can do this
simply by searching for `exported="true"`. Starting from the top of the manifest, we find a couple interesting results:

```
<activity android:theme="@style/AppTheme.NoActionBar" android:label="@string/title_activity_flag_eighteen" android:name="b3nac.injuredandroid.FlagEighteenActivity" android:exported="true"/>
<activity android:theme="@style/AppTheme.NoActionBar" android:label="@string/title_activity_exported_protected_intent" android:name="b3nac.injuredandroid.ExportedProtectedIntent" android:exported="true"/>
<activity android:name="b3nac.injuredandroid.QXV0aA" android:exported="true"/>
```

The first activity is a spoiler, and the third is one we saw in Flag 2. The second one, however, looks extremely promising. Let's check it out:

![exporting_class](https://user-images.githubusercontent.com/86139991/176512558-5668ad48-5181-43ed-b144-3ce3b19db5a5.PNG)

Aha! In the very first function, we see logic that starts another activity. This might be the protected activity "hub" we're looking for.

This function does a couple things. It is called with an Intent, which it checks for the "extra" field `"access_protected_component"`. If it finds it,
and it the activity enclosed in `"access_protected_component"` is part of the package `b3nac.injuredandroid`, it will start the activity for us. This means
that if

- we can invoke this function with an intent
- that has an `"access_protected_component"` field
- which contains an activity that's part of `b3nac.injuredandroid`

then we can start any activity in `b3nac.injuredandroid` externally, exported or not!

Let's tackle these steps one at a time.

### Starting an activity with an intent

Starting from the very bottom, our first task is to call `F()` with an intent we control. Thankfully, the activity is small, so we can quickly find that
`F()` is called in `onResume`:

![on_resume](https://user-images.githubusercontent.com/86139991/176514207-319c23de-97a2-4038-8325-7b0e2dc34433.PNG)

A quick Google search reveals that `onResume` is called when the activity is started (shortly following `onCreate`), so we can call this simply by
starting the activity. Furthermore, the argument to `F` is `getIntent()`, which returns the intent that the activity was resumed with. **Therefore if we
can start the exported activity with an intent we control, we can open any activity in the app!**.

So how do we start an activity with an intent? Well, there's good news and bad news. The good news is that it's very easy. The bad news is that it requires
us to venture into a new territory: *creating our own malicious Android apps*.

### Creating a PoC app

The concept of creating an Android app may seem daunting to the beginner. Worry not -- if you've been following along so far, this can be done in under
ten minutes!

First, we need to open Android Studio. If you've followed these writeups, you will have installed it during our initial setup. If not, you may need to
install it; see the README for instructions.

Once you've opened Android Studio, create a new app. Since we don't need to do anything complicated, let's choose the simplest template: `Empty Activity`.

![empty_activity](https://user-images.githubusercontent.com/86139991/176515172-c2ac9957-a05b-4918-a9ed-f2976e58c4dd.PNG)

Give your new app a name and use the default settings. Once you've done this, you should get an app that looks something like this:

![app_start](https://user-images.githubusercontent.com/86139991/176515365-4247daa8-1a65-4685-af30-22f02e73edf8.PNG)

Don't worry too much about what's already there -- it's mostly boilerplate.

### Declaring intents and starting activities

We've successfully created an Android app. Now, we just have to add code that starts `ExportedProtectedIntent` with the right intent. So, how do we do that?

Let's create the intent that we want to put inside `access_protected_component`. This can be done with one line:

```kotlin
val protectedIntent = Intent()
```

(Make sure to press alt+enter to import the Intent class if necessary!)

Recall that the "hub" activity will start the activity described by this intent, as long as it's part of the package `b3nac.injuredandroid`. We can set the
activity associated with the intent using `setClassName`:

```kotlin
val protectedIntent = Intent()
protectedIntent.setClassName("b3nac.injuredandroid", "b3nac.injuredandroid.FlagTwelveProtectedActivity")
```

And that's it!

Now we need to create the intent which `ExportedProtectedComponent` is started with. We can do this in the exact same way:

```kotlin
val protectedIntent = Intent()
protectedIntent.setClassName("b3nac.injuredandroid", "b3nac.injuredandroid.FlagTwelveProtectedActivity")

val exportedIntent = Intent()
exportedIntent.setClassName("b3nac.injuredandroid", "b3nac.injuredandroid.ExportedProtectedActivity")
```

Now we need to add the "parcelled extra" `access_protected_component`. A "parcelled extra" is basically just an argument to an Intent. This is also
a one-liner:

```kotlin
val protectedIntent = Intent()
protectedIntent.setClassName("b3nac.injuredandroid", "b3nac.injuredandroid.FlagTwelveProtectedActivity")

val exportedIntent = Intent()
exportedIntent.setClassName("b3nac.injuredandroid", "b3nac.injuredandroid.ExportedProtectedActivity")
exportedIntent.putExtra("access_protected_component", protectedIntent)
```

With just five lines of code, we've *almost* solved this flag! There is only one step left. Let's check the source code for `FlagTwelveProtectedActivity`
again and see what it does when it's opened:

![main_class](https://user-images.githubusercontent.com/86139991/176517157-74693cf8-1d7a-44ff-bc58-310f0a6a5b60.PNG)

Like `ExportedProtectedActivity`, this class also uses `getIntent()` to find the `Intent` that started it. It seems to check this intent for the "extra"
field `totally_secure`, and then attempts to parse it as a URL. If this URL has the scheme `"https"`, the flag is unlocked; otherwise, the app returns
early. To pass this check, we need to add this field to the `protectedIntent`:

```kotlin
val protectedIntent = Intent()
protectedIntent.setClassName("b3nac.injuredandroid", "b3nac.injuredandroid.FlagTwelveProtectedActivity")
protectedIntent.putExtra("totally_secure", "https://zombo.com")

val exportedIntent = Intent()
exportedIntent.setClassName("b3nac.injuredandroid", "b3nac.injuredandroid.ExportedProtectedActivity")
exportedIntent.putExtra("access_protected_component", protectedIntent)
```

That seems to be it! Now we just have to add one line that starts `ExportedProtectedActivity` with the right intent:

```kotlin
val protectedIntent = Intent()
protectedIntent.setClassName("b3nac.injuredandroid", "b3nac.injuredandroid.FlagTwelveProtectedActivity")
protectedIntent.putExtra("totally_secure", "https://zombo.com")

val exportedIntent = Intent()
exportedIntent.setClassName("b3nac.injuredandroid", "b3nac.injuredandroid.ExportedProtectedActivity")
exportedIntent.putExtra("access_protected_component", protectedIntent)

startActivity(exportedIntent)
```

### Building and installing our app

If you've gotten this far, congratulations! You've written a malicious PoC app to exploit a vulnerability in another application. This may seem like a simple
accomplishment, but back when you started working through this app, you probably thought it would be quite difficult. You've done it, and congratulations
are in order. Now, let's build our app and get it on the emulator!

This is very easy in Android Studio. We can build our app into an `.apk` (the file format for Android app images) in the menu `Build ->
Build Bundle(s) / APK(s) -> Build APK(s)`:

![build_apk](https://user-images.githubusercontent.com/86139991/176518202-4e08284a-03aa-4f38-a1d9-6513b8b62ea8.PNG)

This might take some time. When it's done, you'll see the following status message:

![build_status_message](https://user-images.githubusercontent.com/86139991/176518396-0ca38df9-3c34-4814-a407-1d7bac38be55.PNG)

Clicking on the `locate` deep link should open a file explorer in the directory that contains your `.apk`. Now all that's left is to install it the same way
we installed Injured Android -- by dragging and dropping the `.apk` onto our emulator!

### Running the malicious app

Once you've installed the app, you can run it by double-clicking on the icon or going to `Settings -> Apps -> YOUR_APP_NAME`. Doing so will call our
`onCreate` function, which will start `ExportedProtectedActivity` with our custom intent, which in turn will start `FlagTwelveProtectedActivity`, which...

![success](https://user-images.githubusercontent.com/86139991/176518947-0ddb5ca6-aeeb-4748-8a41-25b0d73090af.PNG)

Nice!

## The takeaway

So, what did we learn here?

We did quite a bit in this activity. First, we learned about **protected activities** and the exported **hub activities** that call them. Then we created
our very own malicious application that talks to the hub activity and opens the protected activity! This is quite an accomplishment, especially for a
beginner Android researcher. If you've made it this far, pat yourself on the back -- you deserve it.

Next time, we'll chill a bit and learn how to work with the `assets` of an app.
