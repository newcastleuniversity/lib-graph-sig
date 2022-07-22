#!/usr/local/bin/fish
#set pseudonyms (cat pseudonyms-50.txt | string collect)
set pseudonyms (cat pseudonyms-50.txt )
set pseudonymFile pseudonyms-50.txt
set cmd (java -cp target/graph-sig-0.0.1-SNAPSHOT.jar  "uk.ac.ncl.cascade.topographia.Topographia" -s -C --nym $i --verbose)
 
for i in $pseudonyms 
	echo "$i"
	eval (java -cp target/graph-sig-0.0.1-SNAPSHOT.jar  "uk.ac.ncl.cascade.topographia.Topographia" -s -C --nym $i --verbose)  
end
