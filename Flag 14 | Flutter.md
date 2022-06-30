# Flag 14 | Flutter

I will not be covering this activity. This challenge, in my opinion, is poorly constructed. Despite nominally being a XSS challenge, the only way to get the
flag is to reverse engineer an obfuscated Flutter .so (which I will study deeper at a later time) or to guess the specific XSS payload that unlocks the flag.
The intended solution, which is to find the debug information in `assets`, is flat-out broken on the most recent release.
