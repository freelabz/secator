#$ delay 5

secator x # show available tasks
#$ expect \$

secator x httpx mydomain.com:8080
#$ expect \$

secator x httpx mydomain.com:8080 -json # JSON lines, yay !
#$ expect \$

secator u enable-aliases && . ~/.secator/.aliases # we can wrap available tasks as aliases
#$ expect \$

httpx --help # httpx is now secator
#$ expect \$

httpx mydomain.com:8080 -orig -json # in case you want to get the original httpx JSON output
#$ expect \$

listw # show available workflows, same as secator w
#$ expect \$

secator w host_recon mydomain.com # you can also use the alias hostrec mydomain.com as well
#$ expect \$

echo "Thank you !"
#$ expect \$
#$ wait 5000