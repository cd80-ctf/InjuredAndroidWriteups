# Flag 3 | Resources
Welcome back! Last time, we were introduced to *exported activities*, the main external attack surface of an Android application. This time, we're going
to pivot to an *internal* attack surface -- a place where misguided developers often store hardcoded credentials, API endpoints, and other information
that is invaluable to our research.

## The target

Launching the InjuredAndroid app and selecting the third flag, we get a more normal-looking screen than last time:

![main_screen](https://user-images.githubusercontent.com/86139991/173879458-52232521-f591-4f02-b362-aaa2657aee7b.PNG)

Looks like we need to find a string that unlocks the flag, just like in the first task.

## The process

### Reading the manifest

As always, we will start off by reading `AndroidManifest.xml`. Following the naming scheme we've discovered in the last two activities, let's search for
`"flag_three"`:

![manifest](https://user-images.githubusercontent.com/86139991/173879748-f2af2eb7-5495-4f1b-be10-a3b388e613e3.PNG)

Just as we expected, there's an activity which references the class `b3nac.injuredandroid.FlagThreeAction`. Jumping into the decompiler, we immediately
notice an interesting function:

![submit_flag](https://user-images.githubusercontent.com/86139991/173880175-81f1382d-ddf8-414b-90d4-defbf484cbf4.PNG)

This looks almost identical to the function we used to unlock Flag 1. The only difference is, insetad of comparing our input to a hardcoded string,
it's compared to a string stored at `R.string.cmVzb3VyY2VzX3lv`. If we can hunt down this string, we'll have our flag.

### Checking the resources

In Android programming and in general, hardcoding values is generally a bad idea. Instead, such values are often defined in a single, centralized location.
This makes the application much easier to maintain. If we want to change some URL that our application requests, instead of hunting through our code
for every place it shows up, we can just change it in the centralized location. Android agrees with this development philosophy, and all but mandates
that such value are stored in the `Resources` folder.

In our case, we want to find where the string `cmVzb3VyY2VzX3lv` might be stored in the `resources` folder. A quick Google search reveals that
simple strings are often stored in the file `Resources/res/values/strings.xml`. Indeed, checking this file (and similar localized files in
`Resources/res/values-COUNTRYCODE/strings.xml` is a good early step in exploiting any Android application, as it gives you a load of information
about the application, often including API endpoints and external URLs. So let's take a look!

### The weird Jadx bug

Funnily enough, I hit a snag at this point because Jadx refused to display the `Resources/res/values` folder. On the latest Windows release
at time of writing, opening `Resources` in the sidebar would list all the folders correctly until the bottom of the screen, but would then skip
every folder until the last one (`Resources/xml`). To this day, I don't know why this was happening. Very strange.

Luckily, this bug isn't a big deal -- we can search for the string instead.

### Finding the hardcoded flag

We want to find a specific string in the `Resources` folder. One approach would be to hunt through `strings.xml` for the desired value, and this would
indeed give us what we want. However, on larger applications, manually searching can be a pain, so instead we'll use the built-in Jadx search, found
under the menu `Navigation->Text Search`:

Checking the box to search in `Resources` and entering our string, we immediately get what we're looking for:

![search](https://user-images.githubusercontent.com/86139991/173883738-5c0d957b-00ed-4b41-a79e-be7ec53d27ee.PNG)

Looks like a hardcoded flag to me. Entering this into the app:

![success](https://user-images.githubusercontent.com/86139991/173883904-0ea05bcd-5149-49dc-bd09-b0cf7626c8a1.PNG)

Nice.

## The takeaway

So, what did we learn here?

In this challenge, we learned how fruitful it can be to examine an application's resources. Specifically, looking early on at an app's `strings.xml` can
give us invaluable information about the behavior and attack surface of the app. When targeting smaller apps, it's not even unheard of to find
hardcoded credentials inside `strings.xml`. Long story short, we learned you should always look at `strings.xml` early in the research process. 

Next time, we'll finish our survey of the basics by looking at imported classes.
