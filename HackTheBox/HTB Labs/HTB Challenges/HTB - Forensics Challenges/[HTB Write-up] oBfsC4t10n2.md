# [HackTheBox - oBfsC4t10n2](https://app.hackthebox.com/challenges/oBfsC4t10n2)
Created: 22/07/2024 17:05
Last Updated: 22/07/2024 19:06
***
**DIFFICULTY**: Hard
**CATEGORY**: Forensics
**CHALLENGE DESCRIPTION** 
Another Phishing document. Dig in and see if you can find what it executes.
***
## What kind of macro we got again!?
![fada211c5c5b626cdb504b5d9e013ec8.png](../../../../_resources/fada211c5c5b626cdb504b5d9e013ec8.png)

By using `oleid`, we can see that this file was embbeded with XLM Macros

![5ec9b7896a35d179b3fbef5b48892138.png](../../../../_resources/5ec9b7896a35d179b3fbef5b48892138.png)

Now we can use `olevba` to emulate what this XLM macro will do, which we can see that it will download dll file from C2 server then execute it but what we can also see some parts of a flag right there

## So how do we get a flag?

![1987eb6bd5f3d4c8c87d2eb1ae3e4769.png](../../../../_resources/1987eb6bd5f3d4c8c87d2eb1ae3e4769.png)

I saved an output of `olevba` to a text file with `olevba oBfsC4t10n2.xls > olevba.txt` then started analyzed from the top of the result which we can see that a flag will be created using `CONCATENATE` function

![11bc561c318b1b0c4aa4ea91cabddcd2.png](../../../../_resources/11bc561c318b1b0c4aa4ea91cabddcd2.png)

So if we just use `grep -i "concat" olevba.txt` then we will see last part of a flag right there

>Flag
```
HTB{n0w_eXc3l_4.0_M4cr0s_r_b4cK}
```

![3d7023d97d1a611de6c4cc82c551c50d.png](../../../../_resources/3d7023d97d1a611de6c4cc82c551c50d.png)
***

