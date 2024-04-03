#$ delay 5

secator x ffuf http://testphp.vulnweb.com/FUZZ -mc 200 -quiet  # readable output out-of-the-box
#$ expect \$

secator x ffuf http://testphp.vulnweb.com/FUZZ -mc 200 -quiet -raw  # raw output, pipeable to file or other tools
#$ expect \$

secator x ffuf http://testphp.vulnweb.com/FUZZ -mc 200 -quiet -json  # output JSON lines
#$ expect \$

secator x ffuf http://testphp.vulnweb.com/FUZZ -mc 200 -quiet -orig -json  # original ffuf JSON lines
#$ expect \$

secator x ffuf http://testphp.vulnweb.com/FUZZ -mc 200 -quiet -o table,csv,json  # show table, save results to CSV / JSON files
#$ expect \$

#$ wait 1000