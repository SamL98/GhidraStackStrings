# Ghidra Stack Strings

This project provides a first-pass hack for getting stack strings to display in Ghidra's decompiler window.

Here's an example of the results:

![orig](/images/orig.png)

to

![new](/images/new.png)

The methodology is detailed in [here](https://saml98.github.io/jekyll/update/2020/05/03/ghidra-stack-strings.html)

## Dependencies

This project has dependencies?! Yep. Ghidra's built-in assembler kept yelling at me so at 2am, I decided to give up and call `rasm2` as a subprocess. So yeah. You're gonna need radare2. Or some familiarity with the Ghidra API.

## Warnings

Most of this code was hacked together at the wee hours of the night. Therefore, let's just say it's not production quality. There's also some hacks in the code that were specific to the binary I was looking at while developing this. I don't think it's gonna hurt on other binaries (y'never know) but it's unnecessary nonetheless.

Yoour binary also needs `strcpy` for the script to work.

## Usage

Copy all the scripts to `~/ghidra_scripts` or add this directory to the Ghidra script search paths. Then run `deoptimizer.py`.
