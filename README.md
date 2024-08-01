# Pre-Engagement



#### Log all commands of the current session <a href="#log-all-commands-of-the-current-session" id="log-all-commands-of-the-current-session"></a>

```
script $target.log
....
commands and output of commands you ran in that 1 terminal sesssion
....
exit # when finished
```



**Use Cherrytree or OneNote other to document findings...even a text file!**



**Create a screenshot of the selected area and save it at home directory**

```
shift Print Screen
```

#### &#x20;<a href="#set-the-target-ip-address-to-the-usdip-system-variable" id="set-the-target-ip-address-to-the-usdip-system-variable"></a>

#### Set the Target IP Address to the $ip system variable <a href="#set-the-target-ip-address-to-the-usdip-system-variable" id="set-the-target-ip-address-to-the-usdip-system-variable"></a>

```
export ip=target_ip
```

If you're working on a single target it is useful to do the `export ip=target_ip` command before you run Tmux. That way when you create new tabs in Tmux you don't have to run the export command for every new tab.
