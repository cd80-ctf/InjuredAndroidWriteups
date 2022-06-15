# Flag 4 | Exported Broadcast Reciever
Welcome back! Last time, we tracked down imported classes to pass the flag verification function. This time, we'll be doing something very similar
with an added twist: the concept of *exported broadcast recievers*.

## The target

Launching the InjuredAndroid app and selecting the fifth flag, we we find nothing besides a strange message about some `Action`:

![main_screen](https://user-images.githubusercontent.com/86139991/173895621-50721abc-d37a-473e-8f59-a6ade897b222.PNG)

This is similar to the second task. We have to find a way to unlock the flag through triggering some external event.

## The process

### Reading the manifest

As is tradition, we will start off by searching `AndroidManifest.xml` for `"flag_five"`:


Checking out `b3nac.injuredandroid.FlagFiveActivity` in the decompiler, we find no `submitFlag` function (unlike the past several challenges).
However, we do find some extra code in `onCreate`:


This is a bit strange. The code seems to be adding an `onClick` listener to a button, but there's no button in the event. Ignoring that for now,
we see that when the user clicks this nonexistent button, it calls the class member function `H()`, which calls another member function, `F()`:


This is interesting -- `F()` seems to send out some kind of broadcast. The intent declared in the broadcast matches the strange popup we saw when we opened
the challenge. Could this be related to how we get the flag?

### Broadcasts and Broadcast Recievers

Nearly every modern application has some form of event handling. In Android, event handling is done using [Broadcasts](https://developer.android.com/guide/components/broadcasts). 
Every `Broadcast` contains an `Intent`, describing what event the `Broadcast` represents -- for example, the phone changing its wireless network or
entering airplane mode. These `Broadcasts` can be recieved by -- you guessed it -- `BroadcastReciever` classes. When a `BroadcastReciever` recieves a `Broadcast`,
its `onRecieve` method is called. In this way, Android apps can send asynchronous function calls.

In our case, we've found a function that sends a `Broadcast` with the intent `"com.b3nac.injuredandroid.intent.action.CUSTOM_INTENT"`. The natural next step
is to look for a `BroadcastReciever` which handles this event.

Luckily, we don't have to look far. Just before the original class broadcasts the intent, it makes a few suggestive calls regarding some sort of
`FlagFiveReciever`:


We can check that `FlagFiveReciever.x` is, in fact, an instance of `FlagFiveReciever`. Though the exact functions are obfuscated, this code appears to be
applying a filter to this reciever for events with an intent of `"com.b3nac.injuredandroid.intent.action.CUSTOM_INTENT"`. Very promising!

### Examining the reciever

The obvious next step is to examine the decompiled `FlagFiveReciever`:


We can see code near the bottom that seems to unlock the flag. In order to reach it, the field `f1454a` must be `2`. This shouldn't be too hard, since we
can see at the bottom that `f1454a` is incremented by `1` every time `onRecieve` is called.

Recall that when we opened the challenge, it seemed like the request was sent. Could it be as easy as opening it again?


Again?


There we go.

### Viewing the reciever in the manifest

Though it was not necessary for this event, it is important to know that recievers are declared in `AndroidManifest.xml`. If we search for `FlagFiveReciever`,
we'll find its entry:

```
<receiver android:name="b3nac.injuredandroid.FlagFiveReceiver" android:exported="true"/>
```

If you've been following the past flags, this should make your eyebrows perk up: This reciever is **exported**. When an activity is exported, that means
it can be called by an external application. Similarly, if a reciever is external, *it can be triggered by Broadcasts sent by external apps*. In other words,
if our evil app sent a broadcast with the intent `"com.b3nac.injuredandroid.intent.action.CUSTOM_INTENT"`, we would trigger the same reciever. This is
an obvious attack surface. For this reason, exported recievers are always worth noting whenever you skim a manifest.

**As an important note: if a reciever is declared with an <intent-filter>, it is automatically made external unless marked otherwise.**

## The takeaway

So, what did we learn here?

In this challenge, we learned about Broadcasts and BroadcastRecievers. We found a BroadcastReciever that would eventually give us the flag and triggered
the corresponding Broadcast until we got it. We also learned about exported recievers and the attack surface they present.

Next time, we'll reach a fork in the path that we will take both ways: the choice between static and dynamic analysis.
