# Sudo-ku
Joke implementation of doas where you optionally have to solve a sudoku to run a command.  
Came up with the pun first, but realized a reimplementation of sudo would be too much work...  
Also probably not safe to use...

##  Build and install
`zig build`

Pam authentication can be disabled with -Dno-pam  
Default sudo-kuers file can be left uninstalled with -Dno-sudo-kuers  

Make sure to set the setuid bit of sudo-ku, otherwise it will not be very useful.    
And also make the sudo-kuers file read only for non root users and groups.

`chown root: /bin/sudo-ku`  
`chmod 4755 /bin/sudo-ku`  
`chown root: /etc/sudo-kuers`  
`chmod 644 /etc/sudo-kuers`  

If pam is used, remember to add
`auth required pam_unix.so`
to /etc/pam.d/sudo-ku

## Sudo-kuers
/etc/sudo-kuers contains the access rules for sudo-ku.  
The format is similar to doas.  
Lines starting with # are ignored and other lines follow this spec:  
> permit|deny [*options*] for *identity* [as *target*] [cmd *command* [args *arg* ...]]

| *options*                  |                                                                              |
|----------------------------|------------------------------------------------------------------------------|
| nopass                     |  Does not require password authentication                                    |
| nolog                      |  Disables syslog logging                                                     |
| keepenv                    |  Keep all environment variables (except for those set by sudo-ku)            |
| setenv { [*p*[=*v*]] ... } |  Set environment variables, if *p*=$ use the value of callers env            |
| sudoku[=*n*]               |  Require solving sudoku with *n* given cells (default 40) (25 <= *n* <= 80)  |  
| persist[=*n*]              |  Rule does not require auth again until *n* minutes has passed (default 15)  |
> Options can appear multiple times, but only the last instance will be used

*identity*      
> The username or (if prefixed with ':') the group the rule applies to

*target*  
> The user that this rule allows being run as
> Default is all users

*command*  
> The command the rule applies to
> Must be an absolute path
> Default is all commands

*args*  
> The specific arguments this rule applies to
> Default is all args
> If any args are specified, the command has to be run with
> those exact arguments, specified in the same order
> If no *arg* follows args, the command must be run without args


Sudo-ku will use the first rule it finds that matches.  
Options are ignored if deny is used (but invalid options still cause parse errors).  

## Development
If using guix system:
`sudo $(guix system container test-system.scm)`  
starts a container where sudo-ku is a setuid executable
and /etc/sudo-kuers and /etc/pam.d files are installed.  
Login to user 'tester' with password 'tester'


