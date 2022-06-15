# Flag 4 | Login 2
Welcome back! Last time, we delved into resources and how looking through `strings.xml` can reveal useful information about an app. This time, we'll finish
our census of basic concepts by exploiting a task very similar to the first one.

## The target

Launching the InjuredAndroid app and selecting the fourth flag, we find a familiar sight:

![main_screen](https://user-images.githubusercontent.com/86139991/173895621-50721abc-d37a-473e-8f59-a6ade897b222.PNG)

Just like the first task, we need to find a string that unlocks the flag.

## The process

### Reading the manifest

As always, we will start off by searching `AndroidManifest.xml` for `"flag_four"`:

![manifest](https://user-images.githubusercontent.com/86139991/173895823-1f9d3603-6024-43b3-92d8-972a3b63b009.PNG)

As usual, we find an activity which references a class: `b3nac.injuredandroid.FlagFourActivity`. Hopping over to the decompiler, we again find an
interesting function:

![submit_flag](https://user-images.githubusercontent.com/86139991/173896063-4cefb000-78be-4705-8139-9a3611120cab.PNG)

### Finding the imported classes

Again, our target function is comparing our input from `editText2` to a string. This time, however, the comparison string is unclear. In order to figure out
the correct flag, we're going to have to delve into the `imported classes` used to generate it.

First, note that the eventual comparison is between `obj` (our input string) and a string created as `new String(a2, d.w.c.f2418a)`. We need to figure out
what the hell either of those arguments mean. Looking up a bit in the function, it seems like `a2` is created via calls to some more unknown classes,
so let's start with the simpler parameter: `d.w.c.f2418a`.

To figure out where `d.w.c.f2418a` comes from, we should first check the classes defined by the parent class (`b3nac.injuredandroid`). We can see these
in the Jadx sidebar. Finding nothing, our next step is to check classes that are imported by our current class (`FlagFourActivity`). A quick check reveals
that no classes called `d` are imported:

![imports](https://user-images.githubusercontent.com/86139991/173897316-4523ea99-b682-4b1e-a552-79f099b4075e.PNG)

Since we found no relevant imported classes, this `d.w.c.f2418a` import must come from another base-level class. We can see the list of these classes in
the sidebar on Jadx:

![root_classes](https://user-images.githubusercontent.com/86139991/173897744-d5889941-05c8-41da-af0b-2093fdb6f010.PNG)

### The charset class

As expected, we find a `d` class here. Going down the directories, we find the static class `d.w.c`:

![dwc](https://user-images.githubusercontent.com/86139991/173898150-b954f6bb-44e1-45ac-8c8b-8dd793cd2645.PNG)

This class has the property we saw earlier (`f2418a`). Furthermore, we can see that it is set to a variable representing the `UTF-8` charset. Thus
we can guess that `d.w.c.f2418a` is a charset that is used to decode the string in `a2`.

That's it for `d.w.c.f2418a`. Now let's look at the more complicated value, `a2`.

### The decoder class

Looking up a few lines in `FlagFourActivity`, we see that `a2` is a byte array defined as

`byte[] a2 = new g().a()`

The `g` class is obfuscated, as we could guess from the multiple one-letter names. However, the next line gives us a strong hint as to what it's doing:

![decoder_getdata](https://user-images.githubusercontent.com/86139991/173899175-d54f5b84-7cb8-4534-9672-362b8f8a2dbc.PNG)

Even though we know nothing about this function, we can now guess that the `g()` class is a decoder, and the associated function `g.a()` is meant to decode
some data. These sorts of contextual hints are invaluable in attacking a decompiled application, and you should always be on the lookout for them.

Again, our first thought is to look at the other classes defined in `b3nac.injuredandroid`. This time, we find a `g` class:

![g_class](https://user-images.githubusercontent.com/86139991/173899974-ff8baff8-9d59-4bb7-a235-59e2639394a8.PNG)

Bingo. This class decodes a hardcoded base64 string, then returns it through `a()`. Thus the `a2` argument used to create the comparison string is simply
the base64-decoded value of `NF9vdmVyZG9uZV9vbWVsZXRz`. We can plug this into an online base64 decoder to find the flag:

![decoded_flag](https://user-images.githubusercontent.com/86139991/173900857-90cf71ab-0ece-424d-844a-1639aa2c116a.PNG)

Plugging this into the app:

![success](https://user-images.githubusercontent.com/86139991/173900965-a0995d4e-5e59-4fb0-b3f2-53cec503e978.PNG)

Very nice.

## The takeaway

So, what did we learn here?

In this challenge, we learned how to find and analyze imported classes. The first place to look is the classes defined by the same parent class as our target;
failing that, we can check the classes imported at the top of the file; finally, we go up the tree and look at the other classes in the app. By following
this method, we can find, decompile, and analyze any Java or Kotlin code in the app.

If you've gotten this far, congratulations! You have all the basic skills to analyze and attack any Android app of your choosing (as long as it's written
in Java or Kotlin). Next time, we'll take a quick detour to examine another attack surface for Android apps before delving into the more complex material.
