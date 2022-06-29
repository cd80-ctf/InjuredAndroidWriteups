# Flag 11 | Deep Links
If you've gotten this far, you've got a well-rounded skillset for attacking Android apps. In this challenge, you'll expand your toolbox even further and
discover another powerful attack surface: **deep links**, or links opened by apps.

## The target

Launching the InjuredAndroid app and selecting the eleventh flag, we find something startling:

![home_screen](https://user-images.githubusercontent.com/86139991/176257017-eb5efc0c-2f0d-4ce6-a817-e5f4ddc75b9e.PNG)

That's right -- no flag entry screen. In fact, we can't even open the activity. Whatever this is, we're going to have to get at it another way.

## Exploitation

### Reading the manifest

Searching `AndroidManifest.xml` for `"flag_eleven"` gives another dousing of cold water: no results! Clearly, this activity will be different to those
we've completed in the past.

Thankfully, we can still find a related activity. From the title, we know that this challenge will be related to deep links. Thus we should look for
activities that relate to them. Simply searching the manifest for `"deep_link"` gives us what we want:

![manifest](https://user-images.githubusercontent.com/86139991/176258135-323599c8-f7ab-463b-b205-2fdfeaf21439.PNG)

This is more like it. In fact, readers with good memories might recognize something very interesting is going on here right off the bat. Recall from our
daliance with exported intents that *any functionality inside an intent-filter is exported unless marked otherwise*. This means that the
`b3nac.injuredandroid.DeepLinkActivity` class we found is actually exported, and can be accessed from another app!

In order to access this activity, we need to figure out what kind of deep links open it. A deep link is defined in `AndroidManifest.xml` with
three key flags:

- The flag `android.intent.category.DEFAULT`, which allows the activity to be accessed by deep links clicked outside the app,
- The flag `android.intent.category.BROWSABLE`, which allows the activity to be accessed by going to a link in a web browser,
- Most importantly, a `data` flag, which specifies which links this app can open.

The `data` flag contains several fields that dicate which links the app can open. At minimum, every deep link has an `android:schema` flag, which specifies
the connection schemas that it can open. A schema is essentially a connection protocol, like `http`, `https`, or `ftp`. In our case, the most interesting
schema is `flag11`. The presence of this schema means that **opening any link that starts with `flag11://` will trigger the deep link activity.**

### Opening the deeplink

In most cases, a deeplink is opened when a user clicks on or is redirected to it. However, for our purposes, there is an easier way: using the
activity manager via ADB. This is what we did to get at Flag 2.

The command we can use to trigger this deeplink looks like

```
adb shell am start -a android.intent.action.VIEW -d "flag11://"
```

where `am` is the activity manager, `-a` specifies the activity to launch, `android.intent.action.VIEW` is the action declared for this deeplink in
`AndroidManifest.xml`, and `-d` is the URI of the activity, which we have set to trigger the deeplink filter.

Let's see what happens when we run this command:

![deep_link_activated](https://user-images.githubusercontent.com/86139991/176260242-568b5643-905c-4c11-8bd2-3ebea105d08c.PNG)

Now this looks more familiar! By activating the deep link, we have started the activity from outside the app.

## Finding the flag

The hard part of the challenge -- which, funnily, is actually getting to the challenge -- is over. Now we're back on our home turf, and we need to
find the flag.

Let's start at the `submitFlag` function:

![submit_flag](https://user-images.githubusercontent.com/86139991/176261311-6724f877-8ca8-4749-8666-21a699b55a48.PNG)

This looks very familiar. If this is similar to the past several exercises, we should start looking for a Firebase endpoint. Indeed, we can find one
in the instantiator:

![instantiator](https://user-images.githubusercontent.com/86139991/176261533-4b45b07d-ec09-4793-bec2-c5afb8ccdd8f.PNG)

This seems to be accessing a Firebase child value with the name `this.z`, which we can check is hardcoded to `binary/`. As in the past few challenges,
our first instinct is to check to see if it's misconfigured by going to https://injuredandroid.firebaseio.com/binary.json:

![firebase](https://user-images.githubusercontent.com/86139991/176261896-317454b8-bf9a-4207-83ee-1f8f44581828.PNG)

Very nice. Plugging this flag into the app gives us what we want:

![success](https://user-images.githubusercontent.com/86139991/176262411-118abc66-307f-4885-be7c-79c5d4377d37.PNG)

Bingo.

## The takeaway

So, what did we learn here?

The major takeaway from this challenge is to always look for deeplinks. Deeplinks present a great attack surface, since they essentially export their
activities. They can also be found fairly easily by searching the `AndroidManifest.xml` for `android:schema`. Once we had found and activated a deeplink
from outside the application, all we had to do was find an insecure Firebase value.

Next time, we'll step up our abilities by creating our own app to exploit an exported activity.
