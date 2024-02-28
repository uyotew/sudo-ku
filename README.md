run 
$ zig build gen
then, as root, run
$ zig build -p [your-prefix-path]
$ mv zig-out/sudokuers /etc/sudokuers
$ chown root: /etc/sudokuers
$ chmod 644 /etc/sudokuers

/etc/sudokuers contains the access rules for sudo-ku

the format is basically the same as for doas:

permit|deny [options] for identity [as target] [cmd command [args ...]]

options:
  nopass      does not require password
  sudoku[=n]    require solving sudoku with n given cells (default 40) (20 <= n <= 80)
  nolog       disables syslog logging
  persist[=n]   does not require auth until n minutes has passed (default 15)

identity:    
  the username or (if prefixed with ':') the group the rule applies to

target:
  the user that this rule allows running as
  default is all users

command:
  the command the rule applies to
  default is all commands

args:
  the specific arguments this rule applies to
  default is all args
  if no arguments are given after args, the command has to be run without arguments


sudo-ku will use the first rule it finds that matches
options are ignored if deny is used (but invalid options still cause parse errors)
start lines with # to add comments


the command will have the same environment variables as sudo-ku has when invoked

if you want aliases to be expanded, you can add
alias sudo-ku="sudo-ku "
to your bash.rc
