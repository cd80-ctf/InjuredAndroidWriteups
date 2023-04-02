# Flag 16 | CSP Bypass

I will not be covering this activity because (on my Android emulator) the intended solution is broken. However, the concept of CSP bypass (and SSRF in general)
is very useful, so I will cover the concepts included and how one would go about making a solution.

## Content Security Policies

Consider the following scenario, which is very similar to the one in the challenge:

An Android app wants to expose an activity through a deep link. However, it does not want it to be accessible through a browser. That is, if a user clicks
on a deep link in a browser, the deep link should *not* be opened. This is not an unreasonable policy: if a bad guy can trick you into clicking on a deep link
in an email (for example), they would be able to access exported activities unless we have such a filter in place. 

One easy way to implement such a filter is to check the *referer* of the deeplink. (Yes, it's spelled "referer." Yes, it's because the official documents
had a typo.) When a user opens a deep link through an application (like Chrome), the intent sent to the exported activity will put information about
the application that opened it in the `referer` flag. For example, if a deep link is clicked in chrome, `referer` will be set to 
`android-app://com.android.chrome`. If we check for the `referer` tags of popular browsers, we can prevent the deep link from being called from them.

Unless you make a common mistake.

## Server-Side Request Forgery

If you've hunted any web bounties, you might already be familiar with the vulnerability we discuss here. It's still worth skimming, however, as the specifics
on Android are slightly different.

Consider an Android app with deep links on `http` and `https` schemes. Since we're responsible citizens in the 21st century, we want to ensure that everyone
uses `https` and not `http`. One way to do this is simply to detect incoming deep links with the `http` scheme, replace the scheme with `https`, and return
the result. In pseudocode, this might look like this:

```kotlin
if(data.scheme == "http") {
    val newSuperSecureURL = "https://" + data.host + data.path; // replace http requests with https requests
    val newIntent = Intent(Intent.ACTION_VIEW)
    newIntent.data = URI.parse(newSuperSecureURL)
    startActivity(newIntent)
}
```

Wait. Do you see what just happened there?

In the above function, we recieve an intent sent by the user. We parse the intent, use it to build a new one... *and then send the intent ourselves!*
This means that the intent now originates *from the app itself*, rather than from whatever app it started at (like Chrome).

You can see where this is going. Consider an app that filters out deep links from browsers, but contains the above https replacement code. An attacker
can bypass the filter by embedding an `http` deep link in the browser. When the user clicks it, the app will:

- detect that the scheme is `http`,
- construct a new intent with the `https` scheme and attacker-provided data, and
- *send the intent itself*, bypassing the check for a browser-based `referer`!

In essence, we can abuse the bad redirection to pretend that a request is coming from the app, when in reality it came from somewhere else.

Unfortunately, this doesn't work in the app, since `content` links are blocked by default in Chrome. We could set up our own public HTTP server to host
a malicious HTML document with a `http` deep link if we wanted. Consider this a final exercise for the reader.

## The takeaway

So, what's the takeaway here?

In this activity, we learned about a new class of vulnerability called **server-side request forgery** (or SSRF). SSRF happens when an attacker can cause
a target app to re-issue a request. This can often bypass security checks, since requests originating from inside the app are implicitly trusted more
than requests coming from the outside. If you ever venture into webapp bounty hunting, you will see this pattern a lot. Whenever you see a deep link that
filters inputs based on their origin, you should always wonder whether SSRF is possible.

In the next activity, we will consider another security bypass that actually works -- SSL pinning bypass.
