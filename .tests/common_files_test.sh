#!/bin/bash
cp bashScript /bin/bashScript
cp bashScript /bin/bashScriptTwo
chmod 755 /bin/bashScript
chmod 755 /bin/bashScriptTwo
sleep 600
rm -f /bin/bashScript /bin/bashScriptTwo
