# Flags 8 and 9 | Firebase
So far, we've been able to solve every challenge by plumbing through the source code until we found the flag value. No longer! In this task, we're going
to learn how to attack one of the most popular methods that Android apps use to store remote data -- Firebase.

Note that Flag 9 is meant to be an example of AWS exploitation. On some versions of InjuredAndroid, `strings.xml` contains an AWS ID and secret,
which allows an attacker to read data from a bucket containing the flag. However, this is broken on the version we're using -- the `strings.xml` values
are empty. Luckily, this task can be solved the same way as Flag 9, so we have grouped them together.

## The target

Launching the InjuredAndroid app and opening the eighth or ninth flag gives a familiar screen:

![home_screen](https://user-images.githubusercontent.com/86139991/176211661-872e7c53-6615-4684-aa9a-7c1a15cf6d10.PNG)

Our goal is to find the password that unlocks the flag.

## First steps

### Reading the manifest

Searching `AndroidManifest.xml` for `"flag_eight"` gives us the class `b3nac.injuredandroid.FlagEightLoginActivity`, while `"flag_nine"` yields the suggestive
`b3nac.injuredandroid.FlagNineFirebaseActivity`:

![manifest](https://user-images.githubusercontent.com/86139991/176211680-1d1ef0aa-cfa6-4607-986f-944433e562a2.PNG)

As usual, our first instinct is to check the `submitFlag` function. As usual, we find one. However, this one looks markedly different to the others:

![submit_flag](https://user-images.githubusercontent.com/86139991/176211690-79138ffe-6b98-4405-87b4-425af8715362.PNG)

Hmm. In the past, `submitFlag` has usually compared our input directly to another string. This time, however, it's just passing it to a strange function:
`this.y.b()`. What's going on here?

### Using the cross-referencer

The first step is to figure out what the hell `this.y` is. For this, we will use a great feature of the Jadx decompiler that we haven't touched yet --
the *cross-referencer*. The cross-referencer lets us find all the places a variable is used. As you can imagine, this is extremely helpful for exploitation.
If you're ever confused about what some variable or class is, the first thought you have should be to use the cross-referencer.

In our case, we want to find where `this.y` is defined. We can search for this in the cross-referencer simply by putting our cursor on `y` in the function call
and pressing `x`. Doing so brings up two hits in the cross-referencer:

![cross_referencer_output](https://user-images.githubusercontent.com/86139991/176211711-988f5ca6-5771-4401-ad63-9542f3bbf45b.PNG)

Bingo! The first result appears to be the definition of `this.y`. Let's go to it by double clicking on the result:

![cross_referencer_result](https://user-images.githubusercontent.com/86139991/176211726-3ba0cbc5-2f2c-41ba-a5ed-d9e5f9cfd5e7.PNG)

There's a lot going on here. Thankfully, the strings in some of these calls give us some idea of what it is. The app appears to get an instance of something
called a `FirebaseDatabase`, then calls `database.child("aws")` on it. The result of this `database.child()` call is assigned to `this.y`. We can assume
that the call to `this.y.b()` then compares the value we submit to the value in the database. So, how do we find out what's in the database?

(We have covered Flag 8 here, but the process for Flag 9 is very similar -- the only difference is that the argument to `database.child()` needs to be
base64 decoded).

### Reading the Firebase database

This is where some background knowledge comes in handy. Firebase is a basic database service developed by Google and used by millions of Android apps
to store confidential data. When used properly, it is secure. However, it is not uncommon for a Firebase database to be misconfigured. In this case,
an attacker can read or even write to the database, which is a major security issue. As you may guess, the Firebase databases used in Flags 8 and 9
are misconfigured.

But how do we find them? Well, the answers starts with an old friend -- `strings.xml`. Most apps that use Firebase store their database's base URL
in `strings.xml`. Essentially, whenever you notice that an app uses Firebase, you would be behooved to search `strings.xml` for the string `"firebase"`.
If we do this, we'll find the base URL of the database:

![firebase_url](https://user-images.githubusercontent.com/86139991/176211736-ad754a5f-ac3c-4af6-924a-4d33a7cd25fc.PNG)

In the worst case (when the entire database is exposed), we could read it by going to this url and appending `/.json`. Unfortunately, this database is not
*that* poorly configured:

![firebase_base_database](https://user-images.githubusercontent.com/86139991/176211789-b4c3a0f0-d4aa-4903-9dd6-b6567abb2d67.PNG)

However, this doesn't mean that specific children aren't misconfigured. This is where the value passed to `database.child()` and assigned to `this.y`
comes into play. This is the ID of a child value in the database. In Flag 8, this value is hardcoded to `"aws"`; in Flag 9, it is base64-decoded from
`flags`. We can try to access these values from the URL by appending the `CHILD_VALUE.json` to the base URL.

For Flag 8, we can try `https://injuredandroid.firebaseio.com/aws.json`:

![flag_8_db](https://user-images.githubusercontent.com/86139991/176211912-e3988df4-4311-4cde-a7f6-8cb0422bc681.PNG)

For Flag 9, we check `https://injuredandroid.firebaseio.com/flags.json`:

![flag_9_db](https://user-images.githubusercontent.com/86139991/176212037-b9cc225c-f02b-4812-98a3-7052259ff8ca.PNG)

Since both these children are public, we can access them through the web interface. These are the flag values, and submitting them to the app
will get us what we want:

![two_for_one](https://user-images.githubusercontent.com/86139991/176212045-f48dfb6c-01fb-4de9-b680-bb09e9413fed.png)

The two for one special.

## The takeaway

So, what did we learn here?

In this challenge, we were introduced to Firebase databases. These are commonly used by Android aplications, and often misconfigured in a way that's
exploitable. We found the base Firebase url in `strings.xml`, then several child values that were unprotected and could be read by the public.

The entrepreneurial reader who wishes to develop their skills might try to solve Flag 7 with this new knowledge. This is not too hard at all, and would be
a good unguided test of the skills you've learned so far.

Next time, we'll make use of a few old tools and one new exploit.
