As we journeyed through our exploration of what John can do in Single Crack Mode- you may have some ideas about what some good mangling patterns would be, or what patterns your passwords often use- that could be replicated with a certain mangling pattern. The good news is you can define your own sets of rules, which John will use to dynamically create passwords. This is especially useful when you know more information about the password structure of whatever your target is.

In other words, some sites ask you to match a specific type of rules to set your password, for example:

`your password have to contain at least one of the following:

- Capital letter
- Number
- Symbol 

**Note: Custom rules are defined in the `john.conf` file, usually located in `/etc/john/john.conf` if you have installed John using a package manager or built from source with `make` and in `/opt/john/john.conf` on the TryHackMe Attackbox.**

The first line:

`[List.Rules:THMRules]` - Is used to define the name of your rule, this is what you will use to call your custom rule as a John argument.

We then use a regex style pattern match to define where in the word will be modified, again- we will only cover the basic and most common modifiers here:

`Az` - Takes the word and appends it with the characters you define  

`A0` - Takes the word and prepends it with the characters you define  

`c` - Capitalises the character positionally  

These can be used in combination to define where and what in the word you want to modify.

Lastly, we then need to define what characters should be appended, prepended or otherwise included, we do this by adding character sets in square brackets `[ ]` in the order they should be used. These directly follow the modifier patterns inside of double quotes `" "`. Here are some common examples:

`[0-9]` - Will include numbers 0-9  

`[0]` - Will include only the number 0  

`[A-z]` - Will include both upper and lowercase  

`[A-Z]` - Will include only uppercase letters  

`[a-z]` - Will include only lowercase letters  

`[a]` - Will include only a  

`[!£$%@]` - Will include the symbols !£$%@  

Putting this all together, in order to generate a wordlist from the rules that would match the example password "Polopassword1!" (assuming the word polopassword was in our wordlist) we would create a rule entry that looks like this:

`[List.Rules:PoloPassword]`

`cAz"[0-9] [!£$%@]"`

  

In order to:

Capitalise the first  letter - `c`

Append to the end of the word - `Az`

A number in the range 0-9 - `[0-9]`

Followed by a symbol that is one of `[!£$%@]`

  

#### Using Custom Rules

We could then call this custom rule as a John argument using the  `--rule=PoloPassword` flag.  

As a full command: `john --wordlist=[path to wordlist] --rule=PoloPassword [path to file]`